from __future__ import annotations

import json
import math
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any
from urllib.parse import urlparse

from .dlp import BaseDLPProvider
from .models import AgentAction, Decision, EnforcementAction, PolicyConfig, RuleResult


class PolicyEngine:
    _RULE_SEVERITY = {
        "tool_scope": 45,
        "resource_scope": 35,
        "payload_size": 20,
        "rate_limit": 25,
        "prompt_injection": 80,
        "sql_injection": 90,
        "code_injection": 90,
        "exfiltration": 85,
        "retrieval_guard": 85,
        "output_guard": 80,
    }

    def __init__(self, policy: PolicyConfig, dlp_provider: BaseDLPProvider | None = None) -> None:
        self._lock = RLock()
        self.policy = policy
        self._dlp_provider = dlp_provider or BaseDLPProvider()
        self._agent_actions: dict[str, deque[datetime]] = defaultdict(deque)
        self._sensitive_patterns: list[re.Pattern[str]] = []
        self._pii_patterns: list[re.Pattern[str]] = []
        self._prompt_injection_patterns: list[re.Pattern[str]] = []
        self._sql_injection_patterns: list[re.Pattern[str]] = []
        self._code_injection_patterns: list[re.Pattern[str]] = []
        self._retrieval_guard_patterns: list[re.Pattern[str]] = []
        self._output_guard_patterns: list[re.Pattern[str]] = []
        self._bulk_exfil_keywords: list[str] = []
        self._apply_policy(policy)

    def evaluate(self, action: AgentAction) -> tuple[Decision, EnforcementAction, int, float, list[str], list[RuleResult]]:
        with self._lock:
            reasons: list[str] = []
            rule_results: list[RuleResult] = []

            rule_results.append(self._check_tool_scope(action, reasons))
            rule_results.append(self._check_resource_scope(action, reasons))
            rule_results.append(self._check_payload_size(action, reasons))
            rule_results.append(self._check_rate_limit(action, reasons))
            rule_results.append(self._check_prompt_injection(action, reasons))
            rule_results.append(self._check_sql_injection(action, reasons))
            rule_results.append(self._check_code_injection(action, reasons))
            rule_results.append(self._check_retrieval_guard(action, reasons))
            rule_results.append(self._check_output_guard(action, reasons))
            rule_results.append(self._check_exfiltration(action, reasons))

            risk_score, confidence = self._score_risk(rule_results)
            enforcement_action = self._map_action(risk_score)
            decision = Decision.ALLOW if enforcement_action is EnforcementAction.ALLOW else Decision.DENY

            if decision is Decision.ALLOW:
                reasons.append("Action allowed by current policy")
            return decision, enforcement_action, risk_score, confidence, reasons, rule_results

    def set_policy(self, policy: PolicyConfig) -> None:
        with self._lock:
            self._apply_policy(policy)

    def set_dlp_provider(self, provider: BaseDLPProvider) -> None:
        with self._lock:
            self._dlp_provider = provider

    def _apply_policy(self, policy: PolicyConfig) -> None:
        self.policy = policy
        self._sensitive_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.sensitive_regex]
        self._pii_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.pii_regex]
        self._prompt_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.prompt_injection_regex]
        self._sql_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.sql_injection_regex]
        self._code_injection_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.code_injection_regex]
        self._retrieval_guard_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.retrieval_guard_regex]
        self._output_guard_patterns = [re.compile(p, flags=re.IGNORECASE) for p in policy.output_guard_regex]
        self._bulk_exfil_keywords = [k.lower() for k in policy.bulk_exfiltration_keywords]

    def _check_tool_scope(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        allow_tools = self.policy.agent_allow_tools.get(action.agent_id, self.policy.default_allow_tools)
        deny_tools = self.policy.agent_deny_tools.get(action.agent_id, self.policy.default_deny_tools)

        if action.tool in deny_tools:
            msg = f"Tool '{action.tool}' is explicitly denied"
            reasons.append(msg)
            return RuleResult(rule="tool_scope", passed=False, message=msg, severity=self._RULE_SEVERITY["tool_scope"])

        if allow_tools and action.tool not in allow_tools:
            msg = f"Tool '{action.tool}' is not in allowlist"
            reasons.append(msg)
            return RuleResult(rule="tool_scope", passed=False, message=msg, severity=self._RULE_SEVERITY["tool_scope"])

        return RuleResult(rule="tool_scope", passed=True, message="Tool scope check passed", severity=0)

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
        return RuleResult(
            rule="resource_scope",
            passed=False,
            message=msg,
            severity=self._RULE_SEVERITY["resource_scope"],
        )

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
            return RuleResult(rule="rate_limit", passed=False, message=msg, severity=self._RULE_SEVERITY["rate_limit"])

        actions.append(now)
        return RuleResult(rule="rate_limit", passed=True, message="Rate limit check passed", severity=0)

    def _check_payload_size(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        payload_size = len(self._payload_to_text(action.payload).encode("utf-8"))
        if payload_size > self.policy.max_payload_bytes:
            msg = (
                f"Payload too large ({payload_size} bytes). "
                f"Max allowed is {self.policy.max_payload_bytes} bytes"
            )
            reasons.append(msg)
            return RuleResult(
                rule="payload_size",
                passed=False,
                message=msg,
                severity=self._RULE_SEVERITY["payload_size"],
            )
        return RuleResult(rule="payload_size", passed=True, message="Payload size check passed", severity=0)

    def _check_exfiltration(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        text = self._action_to_text(action)

        for finding in self._dlp_provider.inspect(text=text, tenant_id=action.tenant_id):
            msg = f"Enterprise DLP provider match ({finding.category}): {finding.detail}"
            reasons.append(msg)
            return RuleResult(
                rule="exfiltration",
                passed=False,
                message=msg,
                severity=min(100, max(self._RULE_SEVERITY["exfiltration"], finding.severity)),
            )

        for pattern in self._sensitive_patterns:
            if pattern.search(text):
                msg = f"Potential sensitive data detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="exfiltration",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["exfiltration"],
                )

        for token in self._extract_possible_urls(text):
            domain = urlparse(token).netloc.lower()
            if self._is_blocked_domain(domain):
                msg = f"Payload contains blocked destination domain: {domain}"
                reasons.append(msg)
                return RuleResult(
                    rule="exfiltration",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["exfiltration"],
                )

        pii_matches = sum(len(pattern.findall(text)) for pattern in self._pii_patterns)
        if pii_matches >= self.policy.pii_match_threshold:
            msg = (
                f"Potential bulk PII exfiltration detected ({pii_matches} matches, "
                f"threshold {self.policy.pii_match_threshold})"
            )
            reasons.append(msg)
            return RuleResult(
                rule="exfiltration",
                passed=False,
                message=msg,
                severity=self._RULE_SEVERITY["exfiltration"],
            )

        if self._bulk_exfil_keywords and pii_matches > 0:
            lower_text = text.lower()
            if any(keyword in lower_text for keyword in self._bulk_exfil_keywords):
                msg = "Potential data exfiltration intent detected with PII and transfer keywords"
                reasons.append(msg)
                return RuleResult(
                    rule="exfiltration",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["exfiltration"],
                )

        entropy_hits = self._detect_high_entropy_tokens(text)
        if entropy_hits:
            msg = (
                f"Potential token/secret exfiltration detected (high-entropy token: {entropy_hits[0][:8]}...)"
            )
            reasons.append(msg)
            return RuleResult(
                rule="exfiltration",
                passed=False,
                message=msg,
                severity=self._RULE_SEVERITY["exfiltration"],
            )

        return RuleResult(rule="exfiltration", passed=True, message="No exfiltration indicators detected", severity=0)

    def _check_prompt_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._prompt_injection_patterns:
            return RuleResult(rule="prompt_injection", passed=True, message="No prompt injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._prompt_injection_patterns:
            if pattern.search(text):
                msg = f"Potential prompt injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="prompt_injection",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["prompt_injection"],
                )

        return RuleResult(
            rule="prompt_injection",
            passed=True,
            message="No prompt injection indicators detected",
            severity=0,
        )

    def _check_sql_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._sql_injection_patterns:
            return RuleResult(rule="sql_injection", passed=True, message="No SQL injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._sql_injection_patterns:
            if pattern.search(text):
                msg = f"Potential SQL injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="sql_injection",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["sql_injection"],
                )

        return RuleResult(rule="sql_injection", passed=True, message="No SQL injection indicators detected", severity=0)

    def _check_code_injection(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        if not self._code_injection_patterns:
            return RuleResult(rule="code_injection", passed=True, message="No code injection patterns configured")

        text = self._action_to_text(action)
        for pattern in self._code_injection_patterns:
            if pattern.search(text):
                msg = f"Potential code injection detected by pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="code_injection",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["code_injection"],
                )

        return RuleResult(
            rule="code_injection",
            passed=True,
            message="No code injection indicators detected",
            severity=0,
        )

    def _check_retrieval_guard(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        is_retrieval = (action.operation or "").lower().startswith("retrieval")
        if not is_retrieval:
            return RuleResult(rule="retrieval_guard", passed=True, message="Retrieval guard not applicable", severity=0)

        text = self._action_to_text(action)
        for pattern in self._retrieval_guard_patterns:
            if pattern.search(text):
                msg = f"Retrieval guard blocked content pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="retrieval_guard",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["retrieval_guard"],
                )
        return RuleResult(rule="retrieval_guard", passed=True, message="Retrieval guard passed", severity=0)

    def _check_output_guard(self, action: AgentAction, reasons: list[str]) -> RuleResult:
        is_output = (action.operation or "").lower().startswith("output")
        if not is_output:
            return RuleResult(rule="output_guard", passed=True, message="Output guard not applicable", severity=0)

        text = self._action_to_text(action)
        for pattern in self._output_guard_patterns:
            if pattern.search(text):
                msg = f"Output guard blocked content pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="output_guard",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["output_guard"],
                )

        # Output guard also checks for sensitive secret leakage.
        for pattern in self._sensitive_patterns:
            if pattern.search(text):
                msg = f"Output guard detected sensitive leakage pattern: {pattern.pattern}"
                reasons.append(msg)
                return RuleResult(
                    rule="output_guard",
                    passed=False,
                    message=msg,
                    severity=self._RULE_SEVERITY["output_guard"],
                )
        return RuleResult(rule="output_guard", passed=True, message="Output guard passed", severity=0)

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

    def _is_blocked_domain(self, domain: str) -> bool:
        if not domain:
            return False
        domain = domain.split(":")[0]
        for blocked in self.policy.blocked_domains:
            value = blocked.lower()
            if domain == value or domain.endswith(f".{value}"):
                return True
        return False

    def _detect_high_entropy_tokens(self, text: str) -> list[str]:
        tokens = re.findall(r"[A-Za-z0-9+/=_-]{%d,}" % self.policy.entropy_min_length, text)
        suspicious: list[str] = []
        for token in tokens:
            entropy = self._shannon_entropy(token)
            if entropy >= self.policy.entropy_threshold:
                suspicious.append(token)
        return suspicious

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        entropy = 0.0
        length = len(value)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _score_risk(self, rule_results: list[RuleResult]) -> tuple[int, float]:
        failed = [result for result in rule_results if not result.passed]
        if not failed:
            return 0, 0.95

        # Weighted blend: strongest failing rule + diminishing contribution of others.
        severities = sorted((result.severity for result in failed), reverse=True)
        score = severities[0]
        for idx, value in enumerate(severities[1:], start=1):
            score += value / (idx + 1)
        risk_score = min(100, int(round(score)))

        if risk_score >= 90:
            confidence = 0.99
        elif risk_score >= 70:
            confidence = 0.95
        elif risk_score >= 50:
            confidence = 0.88
        else:
            confidence = 0.8
        return risk_score, confidence

    @staticmethod
    def _map_action(risk_score: int) -> EnforcementAction:
        if risk_score == 0:
            return EnforcementAction.ALLOW
        if risk_score >= 80:
            return EnforcementAction.DENY
        if risk_score >= 50:
            return EnforcementAction.QUARANTINE
        return EnforcementAction.REVIEW
