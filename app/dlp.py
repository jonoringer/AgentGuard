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


class AWSComprehendPIIProvider(BaseDLPProvider):
    def __init__(self, region: str) -> None:
        self.region = region

    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        try:
            import boto3
        except Exception:
            return []

        try:
            client = boto3.client("comprehend", region_name=self.region)
            resp = client.detect_pii_entities(Text=text[:5000], LanguageCode="en")
        except Exception:
            return []

        findings: list[DLPFinding] = []
        for entity in resp.get("Entities", []):
            findings.append(
                DLPFinding(
                    provider="aws_comprehend",
                    category=str(entity.get("Type", "PII")),
                    detail=f"PII entity score={entity.get('Score', 0):.2f}",
                    severity=85,
                )
            )
        return findings


class GCPDLPProvider(BaseDLPProvider):
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id

    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        try:
            from google.cloud import dlp_v2
        except Exception:
            return []

        try:
            client = dlp_v2.DlpServiceClient()
            parent = f"projects/{self.project_id}/locations/global"
            request = {
                "parent": parent,
                "item": {"value": text[:10000]},
                "inspect_config": {"include_quote": False, "min_likelihood": "POSSIBLE"},
            }
            resp = client.inspect_content(request=request)
        except Exception:
            return []

        findings: list[DLPFinding] = []
        for finding in resp.result.findings:
            findings.append(
                DLPFinding(
                    provider="gcp_dlp",
                    category=str(finding.info_type.name or "PII"),
                    detail=f"likelihood={finding.likelihood.name}",
                    severity=85,
                )
            )
        return findings


class PresidioDLPProvider(BaseDLPProvider):
    def __init__(self, language: str = "en") -> None:
        self.language = language

    def inspect(self, text: str, tenant_id: str | None = None) -> list[DLPFinding]:
        try:
            from presidio_analyzer import AnalyzerEngine
        except Exception:
            return []

        try:
            analyzer = AnalyzerEngine()
            results = analyzer.analyze(text=text[:10000], language=self.language)
        except Exception:
            return []

        findings: list[DLPFinding] = []
        for result in results:
            findings.append(
                DLPFinding(
                    provider="presidio",
                    category=result.entity_type,
                    detail=f"score={result.score:.2f}",
                    severity=80,
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
    providers: list[BaseDLPProvider] = []

    aws_region = os.getenv("AGENTGUARD_DLP_AWS_REGION", "").strip()
    if aws_region:
        providers.append(AWSComprehendPIIProvider(region=aws_region))

    gcp_project = os.getenv("AGENTGUARD_DLP_GCP_PROJECT", "").strip()
    if gcp_project:
        providers.append(GCPDLPProvider(project_id=gcp_project))

    presidio_enabled = os.getenv("AGENTGUARD_DLP_PRESIDIO", "0").strip().lower() in {"1", "true", "yes"}
    if presidio_enabled:
        providers.append(PresidioDLPProvider())

    endpoint = os.getenv("AGENTGUARD_DLP_HTTP_ENDPOINT", "").strip()
    if endpoint:
        api_key = os.getenv("AGENTGUARD_DLP_HTTP_API_KEY", "").strip() or None
        providers.append(HTTPDLPProvider(endpoint=endpoint, api_key=api_key))

    if not providers:
        return BaseDLPProvider()
    return CompositeDLPProvider(providers)
