import structlog

from typing import Any
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource

# from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.instrumentation.django import DjangoInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor


def configure_structlog():
    structlog.configure(
        processors=[
            # Basic filtering and metadata
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            # exception processors
            structlog.dev.set_exc_info,
            # structlog.tracebacks.ExceptionDictTransformer(),
            structlog.processors.format_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def initialize_tracer():
    resource = Resource.create({"service.name": "scirius"})

    # Set up the tracer provider
    tracer_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer_provider)

    # send traces
    tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    DjangoInstrumentor().instrument()
    LoggingInstrumentor().instrument(set_logging_format=True)


def add_otel_fields_to_event_dict(_logger, _method_name, event_dict: dict[str, Any]) -> dict[str, Any]:
    record = event_dict.get("_record")
    span = trace.get_current_span()
    if record and hasattr(record, "trace_id") and record.trace_id != 0:
        event_dict["trace_id"] = format(record.trace_id, "032x")
        event_dict["span_id"] = format(record.span_id, "016x")
    elif not span:
        event_dict["trace_id"] = None
        event_dict["span_id"] = None
    else:
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            event_dict["trace_id"] = format(ctx.trace_id, "032x")
            event_dict["span_id"] = format(ctx.span_id, "016x")
        else:
            event_dict["trace_id"] = None
            event_dict["span_id"] = None
    return event_dict


STRUCTLOG_FOREIGN_PRE_CHAIN = [
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    add_otel_fields_to_event_dict,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.StackInfoRenderer(),
    structlog.dev.set_exc_info,
    structlog.processors.format_exc_info,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.UnicodeDecoder(),
]
