from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class AgentAction(BaseModel):
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


class EvaluationResponse(BaseModel):
    decision: Decision
    reasons: list[str]
    rule_results: list[RuleResult]
    audit_id: str


class AuditRecord(BaseModel):
    audit_id: str
    action: AgentAction
    decision: Decision
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
    prompt_injection_regex: list[str] = Field(default_factory=list)
    sql_injection_regex: list[str] = Field(default_factory=list)
    code_injection_regex: list[str] = Field(default_factory=list)
