import unittest
import os
import tempfile

from fastapi.testclient import TestClient

from app.main import create_app


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["AGENTGUARD_AUDIT_DB"] = f"{self._tmpdir.name}/audit.db"
        os.environ["AGENTGUARD_POLICY_DB"] = f"{self._tmpdir.name}/policy.db"
        self.client = TestClient(create_app())

    def tearDown(self) -> None:
        os.environ.pop("AGENTGUARD_AUDIT_DB", None)
        os.environ.pop("AGENTGUARD_POLICY_DB", None)
        os.environ.pop("AGENTGUARD_API_KEYS", None)
        self._tmpdir.cleanup()

    def test_evaluate_endpoint_and_audit_log(self) -> None:
        response = self.client.post(
            "/v1/guard/evaluate",
            json={
                "agent_id": "build-bot",
                "tool": "exec_shell",
                "payload": {"cmd": "cat /etc/passwd"},
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decision"], "deny")
        self.assertIn(body["enforcement_action"], ["review", "quarantine", "deny"])
        self.assertGreaterEqual(body["risk_score"], 1)
        self.assertLessEqual(body["risk_score"], 100)
        self.assertGreaterEqual(body["confidence"], 0.0)
        self.assertLessEqual(body["confidence"], 1.0)
        self.assertTrue(body["audit_id"])

        logs = self.client.get("/v1/audit/logs", params={"agent_id": "build-bot", "limit": 5})
        self.assertEqual(logs.status_code, 200)
        self.assertGreaterEqual(len(logs.json()), 1)

    def test_auth_is_enforced_when_api_keys_configured(self) -> None:
        os.environ["AGENTGUARD_API_KEYS"] = "viewer-key:viewer,admin-key:admin,operator-key:operator"
        client = TestClient(create_app())

        unauth = client.post(
            "/v1/guard/evaluate",
            json={"agent_id": "build-bot", "tool": "read_file", "payload": {"path": "README.md"}},
        )
        self.assertEqual(unauth.status_code, 401)

        ok = client.post(
            "/v1/guard/evaluate",
            headers={"x-api-key": "operator-key"},
            json={"agent_id": "build-bot", "tool": "read_file", "payload": {"path": "README.md"}},
        )
        self.assertEqual(ok.status_code, 200)

    def test_policy_propose_and_approve_flow(self) -> None:
        os.environ["AGENTGUARD_API_KEYS"] = "admin-key:admin,viewer-key:viewer"
        client = TestClient(create_app())

        current = client.get("/v1/policy/current", headers={"x-api-key": "viewer-key"})
        self.assertEqual(current.status_code, 200)
        base_version = current.json()["version"]
        policy_payload = current.json()["policy"]
        policy_payload["rate_limit_per_minute"] = 10

        proposed = client.post(
            "/v1/policy/propose",
            headers={"x-api-key": "admin-key"},
            json={"actor": "security-admin", "policy": policy_payload},
        )
        self.assertEqual(proposed.status_code, 200)
        proposed_version = proposed.json()["version"]
        self.assertGreater(proposed_version, base_version)

        approved = client.post(
            f"/v1/policy/{proposed_version}/approve",
            headers={"x-api-key": "admin-key"},
            json={"actor": "security-admin"},
        )
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["version"], proposed_version)
        self.assertEqual(approved.json()["policy"]["rate_limit_per_minute"], 10)


if __name__ == "__main__":
    unittest.main()
