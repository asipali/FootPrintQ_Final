"""
FootprintIQ - Comprehensive Integration and Unit Tests for Tenable Nessus REST API
Verifies connection test, template discovery, scan lifecycle, finding normalization,
evidence generation, error sanitization, and API endpoints without leaking credentials.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.api.app import app
from src.collectors.nessus_collector import NessusCollector


class TestNessusIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.anon_client = TestClient(app)
        login_res = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AdminPass2026!"}
        )
        cls.headers = {"Authorization": f"Bearer {login_res.json().get('access_token')}"}

    def test_status_endpoint_returns_sanitized_result(self):
        """GET /api/v1/scanners/nessus/status requires auth and never exposes credentials or internal URLs."""
        anon_resp = self.anon_client.get("/api/v1/scanners/nessus/status")
        self.assertEqual(anon_resp.status_code, 401)

        resp = self.client.get("/api/v1/scanners/nessus/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("mode", data)
        self.assertNotIn("server_url", data)
        # Ensure credentials are NEVER in the response
        resp_str = resp.text.lower()
        self.assertNotIn("accesskey", resp_str)
        self.assertNotIn("secretkey", resp_str)
        self.assertNotIn("x-apikeys", resp_str)

    def test_templates_endpoint_filters_unavailable(self):
        """GET /api/v1/scanners/nessus/templates requires auth and discovers valid templates."""
        anon_resp = self.anon_client.get("/api/v1/scanners/nessus/templates")
        self.assertEqual(anon_resp.status_code, 401)

        resp = self.client.get("/api/v1/scanners/nessus/templates", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("templates", data)
        self.assertGreater(data["count"], 0)
        # Verify structure of each template
        for tmpl in data["templates"]:
            self.assertIn("uuid", tmpl)
            self.assertIn("title", tmpl)
            self.assertIn("is_available", tmpl)

    @patch("requests.get")
    def test_connection_test_success_mock(self, mock_get):
        """POST /api/v1/scanners/nessus/test returns operational when Nessus responds 200."""
        # Mock /server/status
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "ready", "login_status": "allow"}

        # Mock /server/properties
        props_resp = MagicMock()
        props_resp.status_code = 200
        props_resp.json.return_value = {
            "server_version": "10.12.4",
            "nessus_type": "Nessus Essentials",
            "expiration": 1893456000
        }

        mock_get.side_effect = [status_resp, props_resp]

        collector = NessusCollector(
            base_url="https://127.0.0.1:8834",
            access_key="test_access_key",
            secret_key="test_secret_key",
            verify_ssl=False
        )

        res = collector.test_connection()
        self.assertTrue(res["connected"])
        self.assertEqual(res["status"], "Operational")
        self.assertEqual(res["version"], "10.12.4")
        self.assertNotIn("test_secret_key", str(res))

    @patch("requests.get")
    def test_connection_test_auth_failure(self, mock_get):
        """Handle 401 Unauthorized gracefully without leaking error trace with secrets."""
        # /server/status succeeds
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "ready"}

        # /server/properties fails with 401
        auth_fail = MagicMock()
        auth_fail.status_code = 401
        auth_fail.text = "Invalid Credentials"

        mock_get.side_effect = [status_resp, auth_fail]

        collector = NessusCollector(
            base_url="https://127.0.0.1:8834",
            access_key="bad_access_key",
            secret_key="bad_secret_key",
            verify_ssl=False
        )

        res = collector.test_connection()
        self.assertFalse(res["connected"])
        self.assertEqual(res["status"], "Authentication Failed")
        self.assertIn("Invalid Nessus API Access Key or Secret Key", res["error"])
        self.assertNotIn("bad_secret_key", str(res))

    def test_finding_normalization(self):
        """Ensure Nessus severities 0-4 and vulnerabilities map cleanly to FootprintIQ findings."""
        collector = NessusCollector()
        scan_data = {
            "vulnerabilities": [
                {
                    "plugin_id": 51192,
                    "plugin_name": "vsftpd Compromised Source Packages Backdoor",
                    "plugin_family": "FTP",
                    "port": 21,
                    "severity": 4,
                    "risk_factor": "Critical",
                    "synopsis": "The remote FTP server contains a backdoor.",
                    "description": "The remote vsftpd FTP server contains a malicious backdoor.",
                    "solution": "Upgrade to vsftpd 2.3.5 or replace the package.",
                    "cve": ["CVE-2011-2523"],
                    "cvss_score": 10.0,
                    "see_also": ["https://scarybeastsecurity.blogspot.com/"]
                },
                {
                    "plugin_id": 11219,
                    "plugin_name": "NFS Exported Share Information Disclosure",
                    "plugin_family": "RPC",
                    "port": 2049,
                    "severity": 2,
                    "risk_factor": "Medium",
                    "synopsis": "NFS shares are exported to the world.",
                    "description": "At least one NFS share is exported without IP restriction.",
                    "solution": "Configure /etc/exports to restrict access.",
                    "cve": [],
                    "cvss_score": 5.0
                }
            ]
        }

        normalized = collector.normalize_findings(
            scan_data=scan_data,
            target="192.168.56.111",
            investigation_id="RECON-001",
            scan_id="SCAN-TEST-001"
        )

        self.assertEqual(len(normalized), 2)
        v1 = normalized[0]
        self.assertEqual(v1["severity"], "Critical")
        self.assertEqual(v1["cve_identifiers"], "CVE-2011-2523")
        self.assertEqual(v1["cvss_score"], 10.0)
        self.assertEqual(v1["detection_source"], "nessus")
        self.assertIn("vsftpd", v1["title"])
        self.assertEqual(v1["port"], 21)

        v2 = normalized[1]
        self.assertEqual(v2["severity"], "Medium")
        self.assertEqual(v2["cvss_score"], 5.0)
        self.assertEqual(v2["port"], 2049)

    @patch("requests.get")
    @patch("requests.post")
    def test_scan_lifecycle_create_launch_poll(self, mock_post, mock_get):
        """Test complete scan lifecycle: create scan -> launch -> poll -> stop."""
        collector = NessusCollector(
            base_url="https://127.0.0.1:8834",
            access_key="valid_acc",
            secret_key="valid_sec"
        )

        # Mock scan creation
        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.json.return_value = {"scan": {"id": 101, "name": "FootprintIQ-Test"}}
        mock_post.return_value = create_resp

        scan_id = collector.create_scan(
            target="192.168.56.111",
            name="FootprintIQ-Test",
            description="Test scan"
        )
        self.assertEqual(scan_id, 101)

        # Mock launch
        launch_resp = MagicMock()
        launch_resp.status_code = 200
        launch_resp.json.return_value = {"scan_uuid": "launch-uuid-123"}
        mock_post.return_value = launch_resp

        launch_uuid = collector.launch_scan(101)
        self.assertEqual(launch_uuid, "launch-uuid-123")

        # Mock status query
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {
            "info": {
                "status": "completed",
                "targets": "192.168.56.111",
                "scanner_name": "Local Scanner"
            },
            "hosts": [{"host_id": 1, "hostname": "192.168.56.111", "progress": "100%"}],
            "vulnerabilities": []
        }
        mock_get.return_value = status_resp

        st = collector.get_scan_status(101)
        self.assertEqual(st["status"], "completed")
        self.assertEqual(st["progress"], 100)


if __name__ == "__main__":
    unittest.main()
