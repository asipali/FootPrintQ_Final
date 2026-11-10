"""
FootprintIQ - Unit Tests for FastAPI Application and API Routers
"""

import unittest
from fastapi.testclient import TestClient
from src.api.app import app


class TestFootprintIQAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Authenticate admin
        resp = cls.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass2026!"})
        cls.token = resp.json().get("access_token")
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_health_endpoint(self):
        resp = self.client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["platform"], "FootprintIQ")
        self.assertIn("database", data)
        self.assertIn("object_storage", data)
        self.assertIn("network_scanner", data)

    def test_investigations_lifecycle(self):
        # Create
        create_resp = self.client.post(
            "/api/v1/investigations",
            json={"title": "Automated Unit Test Investigation", "description": "CI test run"},
            headers=self.headers
        )
        self.assertEqual(create_resp.status_code, 201)
        inv = create_resp.json()
        inv_id = inv["investigation_id"]
        self.assertTrue(inv_id.startswith("INV-"))

        # List
        list_resp = self.client.get("/api/v1/investigations", headers=self.headers)
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(i["investigation_id"] == inv_id for i in list_resp.json()))

        # Get details
        get_resp = self.client.get(f"/api/v1/investigations/{inv_id}", headers=self.headers)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["title"], "Automated Unit Test Investigation")

    def test_targets_endpoint(self):
        # Add target
        target_resp = self.client.post(
            "/api/v1/targets",
            json={
                "investigation_id": "INV-UNIT-01",
                "target": "192.168.56.111",
                "name": "Metasploitable2 VM",
                "scope": "192.168.56.0/24"
            },
            headers=self.headers
        )
        self.assertEqual(target_resp.status_code, 201)
        self.assertEqual(target_resp.json()["target"], "192.168.56.111")

        # List targets
        list_resp = self.client.get("/api/v1/targets", headers=self.headers)
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(t["target"] == "192.168.56.111" for t in list_resp.json()))

    def test_scan_unauthorized_target_rejection(self):
        resp = self.client.post(
            "/api/v1/scans",
            json={
                "investigation_id": "INV-UNIT-01",
                "scan_type": "nmap_nse",
                "target": "8.8.8.8"
            },
            headers=self.headers
        )
        self.assertEqual(resp.status_code, 403)

    def test_dashboard_ui_html_response(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("FootprintIQ", resp.text)
        self.assertIn("Investigation Intelligence Dashboard", resp.text)

    def test_reports_generation_and_download(self):
        gen_resp = self.client.post(
            "/api/v1/reports/generate",
            json={"investigation_id": "INV-DEFAULT"},
            headers=self.headers
        )
        self.assertEqual(gen_resp.status_code, 201)
        self.assertTrue(gen_resp.json()["pdf_report_path"].endswith(".pdf"))

        dl_resp = self.client.get("/api/v1/reports/download")
        self.assertEqual(dl_resp.status_code, 200)
        self.assertEqual(dl_resp.headers["content-type"], "application/pdf")
        self.assertGreater(len(dl_resp.content), 1000)


if __name__ == "__main__":
    unittest.main()

