import structlog

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from rules.models.misc import get_system_settings

if get_system_settings(static=True).use_opensearch():
    from opensearchpy import (
        OpenSearch as SearchClient,
        ConnectionError as EngineConnectionError,
        RequestError as EngineRequestError,
        NotFoundError as EngineNotFoundError,
        AuthenticationException as EngineAuthException,
    )

    OS_AVAILABLE = True
    ES_AVAILABLE = False
else:
    from elasticsearch import (
        Elasticsearch as SearchClient,
        ConnectionError as EngineConnectionError,
        RequestError as EngineRequestError,
        NotFoundError as EngineNotFoundError,
        AuthenticationException as EngineAuthException,
    )

    OS_AVAILABLE = False
    ES_AVAILABLE = True

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.instrumentation.elasticsearch import ElasticsearchInstrumentor
    from opentelemetry.propagate import inject

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

# max_result_window: PositiveInt = 10000
# interval_point: PositiveInt = 100


@dataclass
class ESConnectionConfig:
    hosts: str | list[str]
    port: int = 9200
    username: str | None = None
    password: str | None = None
    use_ssl: bool = False
    verify_certs: bool = True
    timeout: int = 30
    max_retries: int = 3
    enable_otel: bool = False
    pool_maxsize: int = 4
    pool_block: bool = True


@dataclass
class HealthStatus:
    status: str  # green, yellow, red
    cluster_name: str
    number_of_nodes: int
    number_of_data_nodes: int
    active_primary_shards: int
    active_shards: int
    relocating_shards: int
    initializing_shards: int
    unassigned_shards: int


@dataclass
class IndexInfo:
    name: str
    health: str
    status: str
    uuid: str
    primary_shards: int
    replica_shards: int
    docs_count: int
    docs_deleted: int
    store_size: str


class SearchEngineException(Exception):
    def __init__(self, message: str, original_exception: Exception | None = None):
        self.message = message
        self.original_exception = original_exception
        super().__init__(message)


class ConnectionException(SearchEngineException):
    pass


class RequestException(SearchEngineException):
    pass


class NotFoundException(SearchEngineException):
    pass


class AuthenticationException(SearchEngineException):
    pass


class BaseSearchConnector(ABC):
    def __init__(self, config: ESConnectionConfig):
        self.config = config
        self.client = None
        self.logger = structlog.get_logger("elasticsearch")

        # OTEL (OpenTelemetry) config
        self.tracer = None
        if config.enable_otel and OTEL_AVAILABLE:
            self.tracer = trace.get_tracer(__name__)
            self.logger.info("OTEL enabled for ES")
        elif config.enable_otel and not OTEL_AVAILABLE:
            self.logger.warning("OTEL unavailable for ES")

    def initialize_client(self) -> None:
        """Initialize client (only called once)"""
        if self.client is None:
            self._create_client()
            self._setup_instrumentation()

    @abstractmethod
    def _create_client(self) -> None:
        pass

    def _setup_instrumentation(self) -> None:
        if (
            self.config.enable_otel
            and OTEL_AVAILABLE
            and not get_system_settings(static=True).use_opensearch_2()
            and not get_system_settings(static=True).use_opensearch_3()
        ):
            ElasticsearchInstrumentor().instrument()

    @contextmanager
    def _trace_operation(self, operation_name: str, **attributes):
        """Context manager to trace operations"""
        if not self.tracer:
            yield None
            return

        with self.tracer.start_as_current_span(
            f"analytics.{operation_name}",
            attributes={"db.operation": operation_name, **attributes},
        ) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                raise

    def _inject_trace_headers(self, headers: dict[str, str] | None = None) -> dict[str, str]:
        """Inject trace headers in queries for telemetry"""
        if headers is None:
            headers = {}

        if self.config.enable_otel and OTEL_AVAILABLE:
            inject(headers)

        return headers

    @abstractmethod
    def _handle_exception(self, e: Exception) -> SearchEngineException:
        """Convert specific exceptions to homogeneous ones"""

    def healthcheck(self) -> HealthStatus:
        """Check cluster health"""
        self.initialize_client()

        with self._trace_operation("healthcheck") as span:
            try:
                response = self.client.cluster.health()

                if span:
                    span.set_attributes(
                        {
                            "db.elasticsearch.cluster.name": response.get("cluster_name", "unknown"),
                            "db.elasticsearch.cluster.status": response.get("status", "unknown"),
                        }
                    )

                return HealthStatus(
                    status=response.get("status", "unknown"),
                    cluster_name=response.get("cluster_name", "unknown"),
                    number_of_nodes=response.get("number_of_nodes", 0),
                    number_of_data_nodes=response.get("number_of_data_nodes", 0),
                    active_primary_shards=response.get("active_primary_shards", 0),
                    active_shards=response.get("active_shards", 0),
                    relocating_shards=response.get("relocating_shards", 0),
                    initializing_shards=response.get("initializing_shards", 0),
                    unassigned_shards=response.get("unassigned_shards", 0),
                )
            except Exception as e:
                raise self._handle_exception(e)

    def get_version(self) -> dict[str, Any]:
        """Get engine version"""
        self.initialize_client()

        with self._trace_operation("get_version") as span:
            try:
                response = self.client.info()

                version_info = {
                    "engine_type": "opensearch_2"
                    if get_system_settings(static=True).use_opensearch_2()
                    else "elasticsearch",
                    "version": response.get("version", {}),
                    "cluster_name": response.get("cluster_name", "unknown"),
                    "cluster_uuid": response.get("cluster_uuid", "unknown"),
                }

                if span:
                    span.set_attributes(
                        {
                            "db.version": version_info["version"].get("number", "unknown"),
                            "db.elasticsearch.cluster.name": version_info["cluster_name"],
                        }
                    )

                return version_info
            except Exception as e:
                raise self._handle_exception(e)

    def get_indices(self) -> list[IndexInfo]:
        self.initialize_client()

        with self._trace_operation("get_indices") as span:
            try:
                # get indicies stats
                cat_response = self.client.cat.indices(
                    format="json",
                    h="index,health,status,uuid,pri,rep,docs.count,docs.deleted,store.size",
                )

                indices = [
                    IndexInfo(
                        name=index_data.get("index", ""),
                        health=index_data.get("health", "unknown"),
                        status=index_data.get("status", "unknown"),
                        uuid=index_data.get("uuid", ""),
                        primary_shards=int(index_data.get("pri", 0)),
                        replica_shards=int(index_data.get("rep", 0)),
                        docs_count=int(index_data.get("docs.count", 0)),
                        docs_deleted=int(index_data.get("docs.deleted", 0)),
                        store_size=index_data.get("store.size", "0b"),
                    )
                    for index_data in cat_response
                ]

                if span:
                    span.set_attribute("db.elasticsearch.indices.count", len(indices))

                return sorted(indices, key=lambda x: x.name)
            except Exception as e:
                raise self._handle_exception(e)

    def execute_query(self, index: str | list[str], query: dict[str, Any], **kwargs) -> dict[str, Any]:
        """
        Perform a query on an index

        Args:
            index: index name
            query: query to perform
            **kwargs: additionnal parameters (size, from_, sort, etc.)

        Returns:
            Query result
        """
        self.initialize_client()

        index_name = ",".join(index) if isinstance(index, list) else index

        with self._trace_operation("search", **{"db.elasticsearch.index": index_name}) as span:
            try:
                search_params = {
                    "index": index,
                    "body": query,
                    "request_timeout": 30,
                    "size": 10000,  # MAX_RESULT_WINDOW
                    "ignore_unavailable": True,
                    "_source": True,
                    **kwargs,
                }

                response: dict[str, Any] = self.client.search(**search_params)

                if span:
                    hits = response.get("hits", {})
                    span.set_attributes(
                        {
                            "db.elasticsearch.query.hits.total": hits.get("total", {}).get("value", 0),
                            "db.elasticsearch.query.took": response.get("took", 0),
                            "db.elasticsearch.query.timed_out": response.get("timed_out", False),
                        }
                    )

                return response
            except Exception as e:
                raise self._handle_exception(e)

    def count_documents(self, index: str, query: dict[str, Any] | None = None) -> int:
        """Count index documents"""
        self.initialize_client()

        with self._trace_operation("count", **{"db.elasticsearch.index": index}) as span:
            try:
                count_params = {"index": index}
                if query:
                    count_params["body"] = query

                response = self.client.count(**count_params)
                count: int = response.get("count", 0)

                if span:
                    span.set_attribute("db.elasticsearch.query.count", count)

                return count
            except Exception as e:
                raise self._handle_exception(e)

    def get_mapping(self, index: str) -> dict[str, Any]:
        self.initialize_client()

        with self._trace_operation("get_mapping", **{"db.elasticsearch.index": index}):
            try:
                return self.client.indices.get_mapping(index=index)
            except Exception as e:
                raise self._handle_exception(e)


class ElasticsearchConnector(BaseSearchConnector):
    def __init__(self, config: ESConnectionConfig):
        if not ES_AVAILABLE:
            raise ImportError("elasticsearch module not installed")

        super().__init__(config)

    def _create_client(self) -> None:
        try:
            client_config = {
                "hosts": self.config.hosts if isinstance(self.config.hosts, list) else [self.config.hosts],
                "timeout": self.config.timeout,
                "max_retries": self.config.max_retries,
                "retry_on_timeout": True,
                "maxsize": self.config.pool_maxsize,
                "block": self.config.pool_block,
            }

            if self.config.username and self.config.password:
                client_config["http_auth"] = (
                    self.config.username,
                    self.config.password,
                )

            if self.config.use_ssl:
                client_config["use_ssl"] = True
                client_config["verify_certs"] = self.config.verify_certs

            self.client = SearchClient(**client_config)

            # Connection test
            with self._trace_operation("connection_test"):
                self.client.info()

            self.logger.info("ES client successfully initialized")

        except Exception as e:
            raise self._handle_exception(e)

    def _handle_exception(self, e: Exception) -> SearchEngineException:
        if isinstance(e, EngineConnectionError):
            return ConnectionException(f"ES connection error: {e!s}", e)
        if isinstance(e, EngineAuthException):
            return AuthenticationException(
                f"ES auth error: {e!s}",
                e,
            )
        if isinstance(e, EngineNotFoundError):
            return NotFoundException(f"ES ressource not found: {e!s}", e)
        if isinstance(e, EngineRequestError):
            return RequestException(f"ES query error: {e!s}", e)
        return SearchEngineException(f"ES error: {e!s}", e)


class OpenSearchConnector(BaseSearchConnector):
    def __init__(self, config: ESConnectionConfig):
        if not OS_AVAILABLE:
            raise ImportError("opensearch-py is not installed")

        super().__init__(config)

    def _create_client(self) -> None:
        try:
            client_config = {
                "hosts": self.config.hosts if isinstance(self.config.hosts, list) else [self.config.hosts],
                "timeout": self.config.timeout,
                "max_retries": self.config.max_retries,
                "maxsize": self.config.pool_maxsize,
                "block": self.config.pool_block,
            }

            if self.config.username and self.config.password:
                client_config["http_auth"] = (
                    self.config.username,
                    self.config.password,
                )

            if self.config.use_ssl:
                client_config["use_ssl"] = True
                client_config["verify_certs"] = self.config.verify_certs

            self.client = SearchClient(**client_config)

            # Connection test
            with self._trace_operation("connection_test"):
                self.client.info()

            self.logger.info("OS client successfully initialized")

        except Exception as e:
            raise self._handle_exception(e)

    def _handle_exception(self, e: Exception) -> SearchEngineException:
        if isinstance(e, EngineConnectionError):
            return ConnectionException(f"OS connection error: {e!s}", e)
        if isinstance(e, EngineAuthException):
            return AuthenticationException(f"OS auth error: {e!s}", e)
        if isinstance(e, EngineNotFoundError):
            return NotFoundException(f"OS ressource not found: {e!s}", e)
        if isinstance(e, EngineRequestError):
            return RequestException(f"OS query error: {e!s}", e)
        return SearchEngineException(f"OS error: {e!s}", e)


def get_analytic_connector():
    """
    Get the analytics connector that is available on the system with a default configuration
    """
    gsettings = get_system_settings()
    config = ESConnectionConfig(
        hosts=f"http://{settings.ELASTICSEARCH_ADDRESS}/",
        username=gsettings.elasticsearch_user,
        password=gsettings.elasticsearch_pass,
    )
    return OpenSearchConnector(config) if OS_AVAILABLE else ElasticsearchConnector(config)
