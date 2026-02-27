from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from .models import AgentAction, Decision, PolicyConfig, RuleResult


class PolicyEngine:
    def __init__(self, policy: PolicyConfig) -> None:
        self.policy = policy
        self._agent_actions: dict[str, deque[datetime]] = defaultdict(deque)
        self._sensitive_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.sensitive_regex]
        self._prompt_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.prompt_injection_regex]
        self._sql_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.sql_injection_regex]
        self._code_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.code_injection_regex]

    def evaluate(self, action: AgentAction) -> tuple[Decision, list[str], list[RuleResult]]:
        reasons: list[str] = []
        rule_results: list[RuleResult] = []

        rule_results.append(self._check_tool_scope(action, reasons))
        rule_results.append(self._check_resource_scope(action, reasons))
        rule_results.append(self._check_payload_size(action, reasons))
        rule_results.append(self._check_rate_limit(action, reasons))
        rule_results.append(self._check_prompt_injection(action, reasons))
        rule_results.append(self._check_sql_injection(action, reasons))
        rule_results.append(self._check_code_injection(action, reasons))
        rule_results.append(self._check_exfiltration(action, reasons))

        decision = Decision.DENY if reasons else Decision.ALLOW
        if decision is Decision.ALLOW:
            reasons.append("Action allowed by current policy")
        return decision, reasons, rule_results

    def _check_tool_scope(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        allow_tools = self.policy.agent_allow_tools.get(action.agent_id, self.policy.default_allow_tools)
        deny_tools = self.policy.agent_deny_tools.get(action.agent_id, self.policy.default_deny_tools)

        if action.tool in deny_tools:
            msg = f"Tool '{action.tool}' is explicitly denied"
            reasons.append(msg)
            return RuleResult(rule="tool_scope", passed=False, message=msg)

        if allow_tools and action.tool not in allow_tools:
            msg = f"Tool '{action.tool}' is not in allowlist"
            reasons.append(msg)
            return RuleResult(rule="tool_scope", passed=False, message=msg)

        return RuleResult(rule="tool_scope", passed=True, message="Tool scope check passed")

    def _check_resource_scope(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not action.resource:
            return RuleResult(rule="resource_scope", passed=True, message="No resource provided")

        allowed_prefixes = self.policy.resource_prefix_allowlist.get(action.agent_id)
        if not allowed_prefixes:
            return RuleResult(rule="resource_scope", passed=True, message="No resource scope policy for agent")

        if any(action.resource.startswith(prefix) for prefix in allowed_prefixes):
            return RuleResult(rule="resource_scope", passed=True, message="Resource scope check passed")

        msg = f"Resource '{action.resource}' is outside allowed scope"
        reasons.append(msg)
        return RuleResult(rule="resource_scope", passed=False, message=msg)

    def _check_rate_limit(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=1)
        actions = self._agent_actions[action.agent_id]

        while actions and actions[0] < window_start:
            actions.popleft()

        if len(actions) >= self.policy.rate_limit_per_minute:
            msg = (
                f"Rate limit exceeded for agent '{action.agent_id}' "
                f"({self.policy.rate_limit_per_minute}/minute)"
            )
            reasons.append(msg)
            return RuleResult(rule="rate_limit", passed=False, message=msg)

        actions.append(now)
        return RuleResult(rule="rate_limit", passed=True, message="Rate limit check passed")

    def _check_payload_size(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        payload_size = len(self._payload_to_text(action.payload).encode("utf-8"))
        if payload_size > self.policy.max_payload_bytes:
            msg = (
                f"Payload too large ({payload_size} bytes). "
                f"Max allowed is {self.policy.max_payload_bytes} bytes"
            )
            reasons.append(msg)
            return RuleResult(rule="payload_size", passed=False, message=msg)
        return RuleResult(rule="payload_size", passed=True, message="Payload size check passed")

    def _check_exfiltration(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        text = self._payload_to_text(action.payload)

        for pattern in self._sensitive_patterns:
            if pattern.search(text):
                msg = f"Potential sensitive data detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(rule="exfiltration", passed=False, message=msg)

        for token in self._extract_possible_urls(text):
            domain = urlparse(token).netloc.lower()
            if domain in self.policy.blocked_domains:
                msg = f"Payload contains blocked destination domain: {domain}"
                reasons.append(msg)
                return RuleResult(rule="exfiltration", passed=False, message=msg)

        return RuleResult(rule="exfiltration", passed=True, message="No exfiltration indicators detected")

    def _check_prompt_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._prompt_injection_patterns:
            return RuleResult(rule="prompt_injection", passed=True, message="No prompt injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._prompt_injection_patterns:
            if pattern.search(text):
                msg = f"Potential prompt injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(rule="prompt_injection", passed=False, message=msg)

        return RuleResult(rule="prompt_injection", passed=True, message="No prompt injection indicators detected")

    def _check_sql_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._sql_injection_patterns:
            return RuleResult(rule="sql_injection", passed=True, message="No SQL injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._sql_injection_patterns:
            if pattern.search(text):
                msg = f"Potential SQL injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(rule="sql_injection", passed=False, message=msg)

        return RuleResult(rule="sql_injection", passed=True, message="No SQL injection indicators detected")

    def _check_code_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._code_injection_patterns:
            return RuleResult(rule="code_injection", passed=True, message="No code injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._code_injection_patterns:
            if pattern.search(text):
                msg = f"Potential code injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(rule="code_injection", passed=False, message=msg)

        return RuleResult(rule="code_injection", passed=True, message="No code injection indicators detected")

    @staticmethod
    def _payload_to_text(payload: Any) -> str:
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, sort_keys=True, default=str)

    @staticmethod
    def _extract_possible_urls(text: str) -> list[str]:
        return re.findall(r"https?://[^\s\"'<>]+", text)

    def _action_to_text(self, action: AgentAction) -> str:
        parts = [
            action.tool or "",
            action.operation or "",
            action.resource or "",
            self._payload_to_text(action.payload),
            self._payload_to_text(action.metadata),
        ]
        return "\n".join(parts)
