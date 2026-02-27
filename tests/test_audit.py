import tempfile
import unittest

from app.audit import AuditStore
from app.models import AgentAction, AuditRecord, Decision, EnforcementAction, RuleResult


class AuditStoreTests(unittest.TestCase):
    def test_persists_records_in_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = f"{tmpdir}/audit.db"
            store = AuditStore(db_path=db_path)

            record = AuditRecord(
                audit_id=store.new_audit_id(),
                action=AgentAction(agent_id="agent-1", tool="read_file", payload={"path": "README.md"}),
                decision=Decision.ALLOW,
                enforcement_action=EnforcementAction.ALLOW,
                risk_score=0,
                confidence=0.95,
                reasons=["Action allowed by current policy"],
                rule_results=[RuleResult(rule="tool_scope", passed=True, message="ok", severity=0)],
            )
            store.append(record)

            reopened = AuditStore(db_path=db_path)
            rows = reopened.query(agent_id="agent-1", decision=Decision.ALLOW, limit=5)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].audit_id, record.audit_id)
            self.assertEqual(rows[0].enforcement_action.value, "allow")


if __name__ == "__main__":
    unittest.main()
