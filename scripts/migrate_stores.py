from __future__ import annotations

import os

from app.audit import AuditStore
from app.policy_store import PolicyStore
from app.scim_store import SCIMStore


def main() -> None:
    audit_db = os.getenv("AGENTGUARD_AUDIT_DB", "agentguard_audit.db")
    policy_db = os.getenv("AGENTGUARD_POLICY_DB", "agentguard_policy.db")
    scim_db = os.getenv("AGENTGUARD_SCIM_DB", "agentguard_scim.db")

    audit = AuditStore(db_path=audit_db)
    policy = PolicyStore(db_path=policy_db)
    scim = SCIMStore(db_path=scim_db)

    print("migration_status")
    print("- audit_store:", "ok" if audit.ping() else "error")
    print("- policy_store:", "ok" if policy.ping() else "error")
    print("- scim_store:", "ok" if scim.ping() else "error")

    audit.close()
    policy.close()
    scim.close()


if __name__ == "__main__":
    main()
