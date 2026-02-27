from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass


@dataclass
class DLPFinding:
    provider: str
    category: str
    detail: str
    severity: int = 80


class BaseDLPProvider:
    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        return []


class HTTPDLPProvider(BaseDLPProvider):
    def __init__(self, endpoint: str, api_key: str | None = None, timeout_seconds: int = 5) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        payload = {"text": text, "tenant_id": tenant_id}
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = json.load(resp)
        except Exception:
            return []

        findings: list[DLPFinding] = []
        for item in body.get("findings", []):
            findings.append(
                DLPFinding(
                    provider="http",
                    category=str(item.get("category", "unknown")),
                    detail=str(item.get("detail", "external dlp match")),
                    severity=int(item.get("severity", 80)),
                )
            )
        return findings


class CompositeDLPProvider(BaseDLPProvider):
    def __init__(self, providers: list[BaseDLPProvider]) -> None:
        self.providers = providers

    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        findings: list[DLPFinding] = []
        for provider in self.providers:
            findings.extend(provider.inspect(text=text, tenant_id=tenant_id))
        return findings


def load_dlp_provider() -> BaseDLPProvider:
    endpoint = os.getenv("AGENTGUARD_DLP_HTTP_ENDPOINT", "").strip()
    if not endpoint:
        return BaseDLPProvider()
    api_key = os.getenv("AGENTGUARD_DLP_HTTP_API_KEY", "").strip() or None
    return CompositeDLPProvider([HTTPDLPProvider(endpoint=endpoint, api_key=api_key)])
