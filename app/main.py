from __future__ import annotations

import os
import time

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse

from .audit import AuditStore
from .auth import Role, load_auth_manager
from .engine import PolicyEngine
from .models import (
    AgentAction,
    AuditRecord,
    Decision,
    EvaluationResponse,
    PolicyApproveRequest,
    PolicyCurrentResponse,
    PolicyProposeRequest,
    PolicyVersionSummary,
)
from .policy import load_policy
from .policy_store import PolicyStore
from .telemetry import create_telemetry


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard",
        version="0.1.0",
        description="Policy firewall and audit layer for autonomous AI agents",
    )

    policy_path = os.getenv("AGENTGUARD_POLICY", "config/default_policy.json")
    audit_db_path = os.getenv("AGENTGUARD_AUDIT_DB", "agentguard_audit.db")
    policy_db_path = os.getenv("AGENTGUARD_POLICY_DB", "agentguard_policy.db")
    enable_otel = os.getenv("AGENTGUARD_ENABLE_OTEL", "0").lower() in {"1", "true", "yes"}
    otlp_endpoint = os.getenv("AGENTGUARD_OTEL_ENDPOINT")
    service_name = os.getenv("AGENTGUARD_SERVICE_NAME", "agentguard")
    bootstrap_policy = load_policy(policy_path)
    policy_store = PolicyStore(db_path=policy_db_path)
    policy_store.ensure_seed(bootstrap_policy, actor="bootstrap")
    current_policy = policy_store.get_current().policy
    engine = PolicyEngine(current_policy)
    audit = AuditStore(db_path=audit_db_path)
    telemetry = create_telemetry(enable_otel=enable_otel, service_name=service_name, otlp_endpoint=otlp_endpoint)
    auth = load_auth_manager()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/guard/evaluate", response_model=EvaluationResponse)
    def evaluate(
        action: AgentAction,
        _auth=Depends(auth.require_role(Role.OPERATOR)),
    ) -> EvaluationResponse:
        started = time.perf_counter()
        with telemetry.evaluate_span(action.agent_id, action.tool):
            decision, enforcement_action, risk_score, confidence, reasons, rule_results = engine.evaluate(action)
        elapsed_ms = (time.perf_counter() - started) * 1000
        telemetry.record_decision(
            decision=decision.value,
            enforcement_action=enforcement_action.value,
            risk_score=risk_score,
            elapsed_ms=elapsed_ms,
        )
        audit_id = audit.new_audit_id()
        audit_record = AuditRecord(
            audit_id=audit_id,
            action=action,
            decision=decision,
            enforcement_action=enforcement_action,
            risk_score=risk_score,
            confidence=confidence,
            reasons=reasons,
            rule_results=rule_results,
        )
        audit.append(audit_record)
        return EvaluationResponse(
            decision=decision,
            enforcement_action=enforcement_action,
            risk_score=risk_score,
            confidence=confidence,
            reasons=reasons,
            rule_results=rule_results,
            audit_id=audit_id,
        )

    @app.get("/v1/audit/logs", response_model=list[AuditRecord])
    def list_logs(
        agent_id: str | None = Query(default=None),
        decision: Decision | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
        _auth=Depends(auth.require_role(Role.VIEWER)),
    ) -> list[AuditRecord]:
        return audit.query(agent_id=agent_id, decision=decision, limit=limit)

    @app.get("/v1/audit/stream")
    async def stream_logs(_auth=Depends(auth.require_role(Role.VIEWER))) -> StreamingResponse:
        async def event_stream():
            async for record in audit.stream():
                payload = record.model_dump_json()
                yield f"event: audit\ndata: {payload}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.get("/v1/policy/current", response_model=PolicyCurrentResponse)
    def current_policy(_auth=Depends(auth.require_role(Role.VIEWER))) -> PolicyCurrentResponse:
        return policy_store.get_current()

    @app.get("/v1/policy/versions", response_model=list[PolicyVersionSummary])
    def policy_versions(
        limit: int = Query(default=100, ge=1, le=1000),
        _auth=Depends(auth.require_role(Role.VIEWER)),
    ) -> list[PolicyVersionSummary]:
        return policy_store.list_versions(limit=limit)

    @app.post("/v1/policy/propose", response_model=PolicyVersionSummary)
    def propose_policy(
        request: PolicyProposeRequest,
        _auth=Depends(auth.require_role(Role.ADMIN)),
    ) -> PolicyVersionSummary:
        return policy_store.propose(request.policy, actor=request.actor)

    @app.post("/v1/policy/{version}/approve", response_model=PolicyCurrentResponse)
    def approve_policy(
        version: int,
        request: PolicyApproveRequest,
        _auth=Depends(auth.require_role(Role.ADMIN)),
    ) -> PolicyCurrentResponse:
        try:
            approved = policy_store.approve(version, actor=request.actor)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        engine.set_policy(approved.policy)
        return approved

    return app


app = create_app()
