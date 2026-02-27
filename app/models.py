from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class EnforcementAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    REVIEW = "review"


class AgentAction(BaseModel):
    tenant_id: str | None = None
    agent_id: str = Field(..., min_length=1)
    tool: str = Field(..., min_length=1)
    operation: str | None = None
    resource: str | None = None
    payload: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RuleResult(BaseModel):
    rule: str
    passed: bool
    message: str
    severity: int = Field(default=0, ge=0, le=100)


class EvaluationResponse(BaseModel):
    decision: Decision
    enforcement_action: EnforcementAction
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    rule_results: list[RuleResult]
    audit_id: str


class AuditRecord(BaseModel):
    audit_id: str
    action: AgentAction
    decision: Decision
    enforcement_action: EnforcementAction
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    rule_results: list[RuleResult]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyConfig(BaseModel):
    default_allow_tools: list[str] = Field(default_factory=list)
    default_deny_tools: list[str] = Field(default_factory=list)
    agent_allow_tools: dict[str, list[str]] = Field(default_factory=dict)
    agent_deny_tools: dict[str, list[str]] = Field(default_factory=dict)
    resource_prefix_allowlist: dict[str, list[str]] = Field(default_factory=dict)
    rate_limit_per_minute: int = 60
    max_payload_bytes: int = 50_000
    blocked_domains: list[str] = Field(default_factory=list)
    sensitive_regex: list[str] = Field(default_factory=list)
    pii_regex: list[str] = Field(default_factory=list)
    pii_match_threshold: int = 3
    entropy_min_length: int = 20
    entropy_threshold: float = 4.2
    bulk_exfiltration_keywords: list[str] = Field(default_factory=list)
    prompt_injection_regex: list[str] = Field(default_factory=list)
    sql_injection_regex: list[str] = Field(default_factory=list)
    code_injection_regex: list[str] = Field(default_factory=list)


class PolicyVersionSummary(BaseModel):
    tenant_id: str
    version: int
    status: str
    created_at: datetime
    created_by: str
    approved_by: str | None = None


class PolicyCurrentResponse(BaseModel):
    tenant_id: str
    version: int
    status: str
    policy: PolicyConfig
    created_at: datetime
    created_by: str
    approved_by: str | None = None


class PolicyProposeRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1)
    policy: PolicyConfig
    actor: str = Field(..., min_length=1)


class PolicyApproveRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1)
    actor: str = Field(..., min_length=1)
