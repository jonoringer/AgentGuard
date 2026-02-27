import unittest

from fastapi.testclient import TestClient

from app.main import create_app


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app())

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
        self.assertTrue(body["audit_id"])

        logs = self.client.get("/v1/audit/logs", params={"agent_id": "build-bot", "limit": 5})
        self.assertEqual(logs.status_code, 200)
        self.assertGreaterEqual(len(logs.json()), 1)


if __name__ == "__main__":
    unittest.main()
