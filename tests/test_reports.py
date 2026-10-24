import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import app as scanner_app


class ReportWorkflowTests(unittest.TestCase):
    def setUp(self):
        reports_root = os.path.join(scanner_app.app.root_path, "reports")
        os.makedirs(reports_root, exist_ok=True)
        self.temp_dir = tempfile.mkdtemp(prefix="test_reports_", dir=reports_root)
        scanner_app.app.config.update(TESTING=True, REPORTS_DIR=self.temp_dir)
        self.client = scanner_app.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _scan_result(self, scan_type, port, state):
        return {
            "source": "Network Scanner",
            "target": "192.0.2.10",
            "scan_type": scan_type,
            "command": "nmap test",
            "hosts": [{
                "host": "192.0.2.10", "hostname": "", "state": "up",
                "ports": [{"port": port, "protocol": "tcp", "state": state,
                           "service": "https", "product": "", "version": "", "extra": ""}],
                "os_matches": [], "scripts": [], "traceroute": [],
            }],
            "findings": [],
        }

    def test_download_uses_selected_half_open_or_aggressive_report(self):
        half_result = self._scan_result("half_open", 443, "open")
        aggressive_result = self._scan_result("aggressive", 8080, "filtered")
        with patch.object(scanner_app, "run_half_open_scan", return_value=half_result), patch.object(
            scanner_app, "run_aggressive_scan", return_value=aggressive_result
        ):
            half = self.client.post("/network-scan", json={"target": "192.0.2.10", "scan_type": "half_open"}).get_json()
            aggressive = self.client.post("/network-scan", json={"target": "192.0.2.10", "scan_type": "aggressive"}).get_json()

        half_download = self.client.get(f"/download-report?report_id={half['report_id']}")
        aggressive_download = self.client.get(f"/download-report?report_id={aggressive['report_id']}")
        half_html = half_download.get_data(as_text=True)
        aggressive_html = aggressive_download.get_data(as_text=True)

        self.assertEqual(half_download.status_code, 200)
        self.assertEqual(half_download.mimetype, "text/html")
        self.assertIn("half_open", half_html)
        self.assertIn("443/tcp", half_html)
        self.assertIn("open", half_html)
        self.assertNotIn("8080/tcp", half_html)
        half_download.close()
        self.assertIn("aggressive", aggressive_html)
        self.assertIn("8080/tcp", aggressive_html)
        self.assertIn("filtered", aggressive_html)
        self.assertNotIn("443/tcp", aggressive_html)
        aggressive_download.close()
        self.assertTrue(half_download.headers["Content-Disposition"].startswith("attachment;"))

    def test_invalid_or_missing_report_id_returns_error_not_html_download(self):
        self.assertEqual(self.client.get("/download-report").status_code, 400)
        self.assertEqual(self.client.get("/download-report?report_id=../../secret").status_code, 400)
        missing = self.client.get("/download-report?report_id=00000000-0000-4000-8000-000000000000")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.mimetype, "application/json")

    def test_report_generator_handles_empty_optional_network_fields(self):
        result = {"scan_type": "half_open", "hosts": [{"host": "192.0.2.10"}]}
        path = scanner_app._new_report_path()[1]
        scanner_app.generate_html_report("192.0.2.10", [], path, {"network_results": result})
        with open(path, encoding="utf-8") as report:
            content = report.read()
        self.assertIn("No port results returned.", content)
        self.assertIn("half_open", content)

    def test_empty_scan_report_is_explicit_and_does_not_invent_ports(self):
        result = {"scan_type": "half_open", "hosts": []}
        path = scanner_app._new_report_path()[1]
        scanner_app.generate_html_report("192.0.2.10", [], path, {"network_results": result})
        with open(path, encoding="utf-8") as report:
            content = report.read()
        self.assertIn("No port results returned.", content)
        self.assertNotIn("443/tcp", content)


if __name__ == "__main__":
    unittest.main()
