from __future__ import annotations

import json
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path


class NoopTelemetry:
    @contextmanager
    def evaluate_span(self, agent_id: str, tool: str):
        yield

    def record_decision(self, decision: str, enforcement_action: str, risk_score: int, elapsed_ms: float) -> None:
        return


class JSONLTelemetry(NoopTelemetry):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record_decision(self, decision: str, enforcement_action: str, risk_score: int, elapsed_ms: float) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
            "enforcement_action": enforcement_action,
            "risk_score": risk_score,
            "elapsed_ms": elapsed_ms,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload))
            f.write("\n")


class CompositeTelemetry(NoopTelemetry):
    def __init__(self, delegates: list[NoopTelemetry | OTelTelemetry]) -> None:
        self.delegates = delegates

    @contextmanager
    def evaluate_span(self, agent_id: str, tool: str):
        if not self.delegates:
            yield
            return
        # Use the first span-capable delegate as the active span source.
        with self.delegates[0].evaluate_span(agent_id, tool):
            yield

    def record_decision(self, decision: str, enforcement_action: str, risk_score: int, elapsed_ms: float) -> None:
        for delegate in self.delegates:
            delegate.record_decision(decision, enforcement_action, risk_score, elapsed_ms)


class OTelTelemetry:
    def __init__(self, service_name: str = "agentguard", otlp_endpoint: str | None = None) -> None:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        resource = Resource.create({"service.name": service_name})

        tracer_provider = TracerProvider(resource=resource)
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")))
        else:
            tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(tracer_provider)

        metric_readers = []
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

            metric_readers.append(
                PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=f"{otlp_endpoint}/v1/metrics")
                )
            )

        meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
        metrics.set_meter_provider(meter_provider)

        self._tracer = trace.get_tracer(service_name)
        self._meter = metrics.get_meter(service_name)
        self._decision_counter = self._meter.create_counter(
            "agentguard_decisions_total", description="Total decisions by outcome and action"
        )
        self._latency_hist = self._meter.create_histogram(
            "agentguard_evaluate_latency_ms", description="Decision latency in milliseconds"
        )
        self._risk_hist = self._meter.create_histogram(
            "agentguard_risk_score", description="Risk score from evaluation pipeline"
        )

    @contextmanager
    def evaluate_span(self, agent_id: str, tool: str):
        with self._tracer.start_as_current_span("agentguard.evaluate") as span:
            span.set_attribute("agent.id", agent_id)
            span.set_attribute("agent.tool", tool)
            yield

    def record_decision(self, decision: str, enforcement_action: str, risk_score: int, elapsed_ms: float) -> None:
        attrs = {
            "decision": decision,
            "enforcement_action": enforcement_action,
        }
        self._decision_counter.add(1, attrs)
        self._latency_hist.record(elapsed_ms, attrs)
        self._risk_hist.record(float(risk_score), attrs)


def create_telemetry(
    enable_otel: bool,
    service_name: str = "agentguard",
    otlp_endpoint: str | None = None,
    fallback_jsonl_path: str | None = None,
) -> NoopTelemetry | OTelTelemetry:
    delegates: list[NoopTelemetry | OTelTelemetry] = []
    if fallback_jsonl_path:
        delegates.append(JSONLTelemetry(fallback_jsonl_path))

    if not enable_otel:
        if delegates:
            return CompositeTelemetry(delegates)
        return NoopTelemetry()

    try:
        delegates.insert(0, OTelTelemetry(service_name=service_name, otlp_endpoint=otlp_endpoint))
        return CompositeTelemetry(delegates)
    except Exception:
        if delegates:
            return CompositeTelemetry(delegates)
        return NoopTelemetry()
