import os
import sys
import json
import unittest
from unittest.mock import patch, Mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from secret_scanner_utils import (  # noqa: E402
    normalize_gitleaks_record,
    normalize_trufflehog_record,
    persist_secret_leaks,
)


class SecretScannerUtilsTests(unittest.TestCase):
    def test_normalize_gitleaks_record_success(self):
        record = {
            "Secret": "abcd1234",
            "Description": "Generic API key",
            "File": "src/app.py",
            "StartLine": "42",
            "EndLine": "43",
            "RuleID": "generic-api-key",
            "Entropy": 5.5,
            "Match": "key = 'abcd1234'",
            "Fingerprint": "hash",
            "Commit": "deadbeef",
            "Author": "Jane Doe",
            "Email": "jane@example.com",
            "Date": "2024-01-01",
            "Tags": ["generic"],
        }

        normalized = normalize_gitleaks_record(record)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["detector"], "gitleaks")
        self.assertEqual(normalized["secret"], "abcd1234")
        self.assertEqual(normalized["rule_id"], "generic-api-key")
        self.assertEqual(normalized["file_path"], "src/app.py")
        self.assertEqual(normalized["line_start"], 42)
        self.assertEqual(normalized["line_end"], 43)
        self.assertEqual(normalized["confidence"], "high")
        self.assertEqual(normalized["metadata"]["match"], "key = 'abcd1234'")

    def test_normalize_gitleaks_record_missing_secret(self):
        self.assertIsNone(normalize_gitleaks_record({"Description": "no secret"}))

    def test_normalize_trufflehog_record_success(self):
        record = {
            "Raw": "sk_live_example",
            "DetectorName": "HighEntropyStrings",
            "DetectorType": "high-entropy",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "config.js",
                        "line": 100,
                    }
                }
            },
            "Severity": "high",
        }

        normalized = normalize_trufflehog_record(record)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["detector"], "trufflehog")
        self.assertEqual(normalized["secret"], "sk_live_example")
        self.assertEqual(normalized["rule_id"], "HighEntropyStrings")
        self.assertEqual(normalized["file_path"], "config.js")
        self.assertEqual(normalized["line_start"], 100)
        self.assertEqual(normalized["confidence"], "high")
        self.assertIn("detector_name", normalized["metadata"])

    @patch("secret_scanner_utils.requests.post")
    def test_persist_secret_leaks_success(self, mock_post: Mock):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = 2
        mock_post.return_value = mock_resp

        payload = [
            {"detector": "gitleaks", "secret": "a", "metadata": {}},
            {"detector": "trufflehog", "secret": "b", "metadata": {}},
        ]

        inserted = persist_secret_leaks("http://postgrest:3000", 1, "repo", payload, Mock())

        self.assertEqual(inserted, 2)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://postgrest:3000/rpc/upsert_secret_leaks")
        body = json.loads(kwargs["json"]) if isinstance(kwargs.get("json"), str) else kwargs["json"]
        self.assertEqual(body["p_project_id"], 1)
        self.assertEqual(len(body["p_payload"]), 2)

    @patch("secret_scanner_utils.requests.post")
    def test_persist_secret_leaks_failure_returns_zero(self, mock_post: Mock):
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.text = "error"
        mock_post.return_value = mock_resp

        inserted = persist_secret_leaks("http://postgrest:3000", 1, "repo", [{"detector": "gitleaks", "secret": "a"}], Mock())
        self.assertEqual(inserted, 0)


if __name__ == "__main__":
    unittest.main()
