from __future__ import annotations

import os
import time

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse

from .audit import AuditStore
from .auth import AuthContext, Role, load_auth_manager
from .dlp import load_dlp_provider
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
    policy_store.ensure_seed(bootstrap_policy, tenant_id="global", actor="bootstrap")
    dlp_provider = load_dlp_provider()
    tenant_engines: dict[str, PolicyEngine] = {
        "global": PolicyEngine(policy_store.get_current(tenant_id="global").policy, dlp_provider=dlp_provider)
    }
    audit = AuditStore(db_path=audit_db_path)
    telemetry = create_telemetry(enable_otel=enable_otel, service_name=service_name, otlp_endpoint=otlp_endpoint)
    auth = load_auth_manager()

    def _resolve_tenant(auth_context: AuthContext, requested_tenant: str | None) -> str:
        if auth_context.role is Role.ADMIN and not auth_context.tenant_id:
            return requested_tenant or "global"
        if auth_context.tenant_id:
            if requested_tenant and requested_tenant != auth_context.tenant_id:
                raise HTTPException(status_code=403, detail="Cross-tenant access denied")
            return auth_context.tenant_id
        return requested_tenant or "global"

    def _ensure_tenant_policy(tenant_id: str) -> None:
        try:
            policy_store.get_current(tenant_id=tenant_id)
        except RuntimeError:
            global_policy = policy_store.get_current(tenant_id="global").policy
            policy_store.ensure_seed(global_policy, tenant_id=tenant_id, actor="tenant-bootstrap")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/guard/evaluate", response_model=EvaluationResponse)
    def evaluate(
        action: AgentAction,
        auth_context: AuthContext = Depends(auth.require_role(Role.OPERATOR)),
    ) -> EvaluationResponse:
        action.tenant_id = _resolve_tenant(auth_context, action.tenant_id)
        tenant = action.tenant_id or "global"
        _ensure_tenant_policy(tenant)
        if tenant not in tenant_engines:
            try:
                tenant_policy = policy_store.get_current(tenant_id=tenant).policy
            except RuntimeError:
                tenant_policy = policy_store.get_current(tenant_id="global").policy
            tenant_engines[tenant] = PolicyEngine(tenant_policy, dlp_provider=dlp_provider)

        engine = tenant_engines[tenant]

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
        tenant_id: str | None = Query(default=None),
        auth_context: AuthContext = Depends(auth.require_role(Role.VIEWER)),
    ) -> list[AuditRecord]:
        resolved_tenant = _resolve_tenant(auth_context, tenant_id)
        return audit.query(agent_id=agent_id, decision=decision, limit=limit, tenant_id=resolved_tenant)

    @app.get("/v1/audit/stream")
    async def stream_logs(_auth=Depends(auth.require_role(Role.VIEWER))) -> StreamingResponse:
        async def event_stream():
            async for record in audit.stream():
                payload = record.model_dump_json()
                yield f"event: audit\ndata: {payload}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.get("/v1/policy/current", response_model=PolicyCurrentResponse)
    def current_policy(
        tenant_id: str | None = Query(default=None),
        auth_context: AuthContext = Depends(auth.require_role(Role.VIEWER)),
    ) -> PolicyCurrentResponse:
        resolved_tenant = _resolve_tenant(auth_context, tenant_id)
        _ensure_tenant_policy(resolved_tenant)
        return policy_store.get_current(tenant_id=resolved_tenant)

    @app.get("/v1/policy/versions", response_model=list[PolicyVersionSummary])
    def policy_versions(
        limit: int = Query(default=100, ge=1, le=1000),
        tenant_id: str | None = Query(default=None),
        auth_context: AuthContext = Depends(auth.require_role(Role.VIEWER)),
    ) -> list[PolicyVersionSummary]:
        resolved_tenant = _resolve_tenant(auth_context, tenant_id)
        _ensure_tenant_policy(resolved_tenant)
        return policy_store.list_versions(tenant_id=resolved_tenant, limit=limit)

    @app.post("/v1/policy/propose", response_model=PolicyVersionSummary)
    def propose_policy(
        request: PolicyProposeRequest,
        auth_context: AuthContext = Depends(auth.require_role(Role.ADMIN)),
    ) -> PolicyVersionSummary:
        tenant = _resolve_tenant(auth_context, request.tenant_id)
        return policy_store.propose(tenant_id=tenant, policy=request.policy, actor=request.actor)

    @app.post("/v1/policy/{version}/approve", response_model=PolicyCurrentResponse)
    def approve_policy(
        version: int,
        request: PolicyApproveRequest,
        auth_context: AuthContext = Depends(auth.require_role(Role.ADMIN)),
    ) -> PolicyCurrentResponse:
        tenant = _resolve_tenant(auth_context, request.tenant_id)
        try:
            approved = policy_store.approve(tenant_id=tenant, version=version, actor=request.actor)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if tenant in tenant_engines:
            tenant_engines[tenant].set_policy(approved.policy)
        else:
            tenant_engines[tenant] = PolicyEngine(approved.policy, dlp_provider=dlp_provider)
        return approved

    @app.on_event("shutdown")
    def shutdown() -> None:
        audit.close()
        policy_store.close()

    return app


app = create_app()
