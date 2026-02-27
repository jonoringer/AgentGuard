from __future__ import annotations

import json
import logging
import os
import socket
import urllib.request
from pathlib import Path

from .models import AuditRecord

logger = logging.getLogger(__name__)


class BaseSIEMExporter:
    def export(self, record: AuditRecord) -> None:
        return


class JSONLSIEMExporter(BaseSIEMExporter):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, record: AuditRecord) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(record.model_dump_json())
            f.write("\n")


class WebhookSIEMExporter(BaseSIEMExporter):
    def __init__(self, url: str, timeout_seconds: int = 3) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds

    def export(self, record: AuditRecord) -> None:
        req = urllib.request.Request(
            self.url,
            method="POST",
            headers={"content-type": "application/json"},
            data=record.model_dump_json().encode("utf-8"),
        )
        with urllib.request.urlopen(req, timeout=self.timeout_seconds):
            pass


class SyslogSIEMExporter(BaseSIEMExporter):
    def __init__(self, host: str, port: int = 514) -> None:
        self.host = host
        self.port = port

    def export(self, record: AuditRecord) -> None:
        payload = record.model_dump_json().encode("utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, (self.host, self.port))


class CompositeSIEMExporter(BaseSIEMExporter):
    def __init__(self, exporters: list[BaseSIEMExporter]) -> None:
        self.exporters = exporters

    def export(self, record: AuditRecord) -> None:
        for exporter in self.exporters:
            try:
                exporter.export(record)
            except Exception as exc:  # pragma: no cover
                logger.warning("SIEM exporter failed: %s", exc)


def load_siem_exporter() -> BaseSIEMExporter:
    exporters: list[BaseSIEMExporter] = []

    jsonl_path = os.getenv("AGENTGUARD_SIEM_JSONL_PATH", "").strip()
    if jsonl_path:
        exporters.append(JSONLSIEMExporter(jsonl_path))

    webhook_url = os.getenv("AGENTGUARD_SIEM_WEBHOOK_URL", "").strip()
    if webhook_url:
        exporters.append(WebhookSIEMExporter(webhook_url))

    syslog_host = os.getenv("AGENTGUARD_SIEM_SYSLOG_HOST", "").strip()
    if syslog_host:
        port_raw = os.getenv("AGENTGUARD_SIEM_SYSLOG_PORT", "514").strip()
        try:
            port = int(port_raw)
        except ValueError:
            port = 514
        exporters.append(SyslogSIEMExporter(syslog_host, port))

    if not exporters:
        return BaseSIEMExporter()
    return CompositeSIEMExporter(exporters)
