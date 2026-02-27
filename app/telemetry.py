from __future__ import annotations

from contextlib import contextmanager


class NoopTelemetry:
    @contextmanager
    def evaluate_span(self, agent_id: str, tool: str):
        yield

    def record_decision(self, decision: str, enforcement_action: str, risk_score: int, elapsed_ms: float) -> None:
        return


class OTelTelemetry:
    def __init__(self, service_name: str = "agentguard") -> None:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        resource = Resource.create({"service.name": service_name})

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(tracer_provider)

        meter_provider = MeterProvider(resource=resource)
        metrics.set_meter_provider(meter_provider)

        self._tracer = trace.get_tracer(service_name)
        self._meter = metrics.get_meter(service_name)
        self._decision_counter = self._meter.create_counter(
            "agentguard_decisions_total", description="Total decisions by outcome and action"
        )
        self._latency_hist = self._meter.create_histogram(
            "agentguard_evaluate_latency_ms", description="Decision latency in milliseconds"
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
        self._latency_hist.record(float(risk_score), {"metric": "risk_score"})


def create_telemetry(enable_otel: bool) -> NoopTelemetry | OTelTelemetry:
    if not enable_otel:
        return NoopTelemetry()

    try:
        return OTelTelemetry()
    except Exception:
        return NoopTelemetry()
