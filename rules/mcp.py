from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Iterable
from django.conf import settings
from django.http import HttpRequest
from mcp_server import MCPToolset
from pydantic import IPvAnyAddress, PositiveInt
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated

from rules.messages.mcp import (
    AlertMessage,
    MatchedRuleMessage,
    ProductInfoMessage,
    RuleMessage,
    TalkersInfoMessage,
)
from rules.api.permissions import HasGroupPermission
from rules.services.mcp import McpService
from scirius.utils import convert_datetime_to_timestamp


# In the CSR pattern, controllers are responsible to prepare input data for the Service (trim strings, reformat, ...)
# They are also responsible for returning the formatted response and handle exceptions from the Service


def has_group_permission(required_groups: Iterable[str]):
    """
    Decorator to check if the user has the required group permissions.
    It expects the decorated method to be part of a class with a `request` attribute.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # The 'self' here refers to the McpController instance.
            # It provides access to self.request.
            request = self.request

            # 1. Ensure the user is authenticated first
            if not IsAuthenticated().has_permission(request, self):
                raise PermissionDenied

            # 2. Check group permissions
            if not HasGroupPermission.check_perms(request, self, required_groups):
                raise PermissionDenied

            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class McpController(MCPToolset):
    def __init__(self, context=None, request: HttpRequest | None = None, service: McpService | None = None):
        self.service = service if service is not None else McpService()
        super().__init__(context=context, request=request)

    @has_group_permission(required_groups=["rules.events_view"])
    def alert_list(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        ip: IPvAnyAddress | None = None,
        filter: str | None = None,
        raw: bool = False,
        # pagination parameters
        page: PositiveInt = 1,
        limit: PositiveInt = 50,
    ) -> list[AlertMessage] | list[dict[str, Any]]:
        """
        ### IDS Alerts Endpoint 🚨

        This endpoint retrieves a paginated list of **IDS alert events** detected within a specified time interval. It offers powerful filtering options to help you pinpoint specific events or identify unusual network activity.

        ---

        ### Functionality

        * **Time-based Filtering**: This query filters alerts based on a specified `start` and `end` date time.
        * **Anomaly Detection**:
            * Set `outliers=True` to retrieve alert events that have never been seen on a given IP address before. This is an effective way to detect anomalies and infrequent events.
            * Omitting this parameter or setting it to `False` returns all alert events that occurred during the time interval.
        * **Filtering and Pagination**:
            * You can filter alert events by a specific `ip` address or apply a more complex filter using **Lucene syntax** on the Suricata events.
            * Pagination is available via the `page` and `limit` parameters to manage large result sets.

        ---

        ### Parameters & Returns

        * **Args**:
            * `start` (datetime): The start of the time interval in **UTC (ISO 8601)** format. By default, it's 24 hours before the current time or the `end` time.
            * `end` (datetime, optional): The end of the time interval in **UTC (ISO 8601)** format. By default, it's the current time.
            * `ip` (str, optional): The IPv4 or IPv6 address to filter alert events for.
            * `filter` (str, optional): A search filter for Suricata events using **Lucene syntax**.
            * `raw` (bool): If `True`, returns the **raw Suricata events** including detailed protocol information and metadata for in-depth analysis. The default is a more concise representation.
            * `page` (PositiveInt): The page number for the results (default: `1`).
            * `limit` (PositiveInt): The maximum number of events per page (default: `50`).

        * **Returns**:
            * `list[dict]`: A list of dictionaries, with each dictionary representing an IDS alert. The `signature_id` field in the result corresponds to the `SID` field in the Suricata rule.
        """
        if end is None:
            end = datetime.now(timezone.utc)
        if start is None:
            start = end - timedelta(hours=24)

        return self.service.alert_list(
            start=convert_datetime_to_timestamp(start, True),
            end=convert_datetime_to_timestamp(end, True),
            ip=ip,
            filter=filter if filter else "",
            raw=raw,
            page=page,
            limit=limit,
        )

    @has_group_permission(required_groups=["rules.ruleset_policy_view"])
    def rules(self, sid: PositiveInt | list[PositiveInt]) -> list[RuleMessage]:
        """
        Get rule information from the SID (signature_id field in the alert event). Content of the rule is also provided
        in the Suricata format.

        Args:
            sids (int | list[int]): one or multiple signature id to find
        """
        return self.service.rules([sid] if isinstance(sid, int) else sid)

    @has_group_permission(required_groups=["rules.events_view"])
    def talkers(
        self,
        filter: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[TalkersInfoMessage]:
        """
        ### Network Talkers Endpoint 🗣️

        This endpoint retrieves a list of the most active "talkers" (hosts) on the network within a specified time interval. It calculates these talkers based on network events, which can be filtered to focus on specific traffic or indicators of compromise (IOCs).

        ---

        ### Parameters & Returns

        * **Args**:
            * `filter` (str, optional): A filter to apply to network events. This can be a simple string (e.g., an IOC) to search across all fields or a more complex query using **Lucene syntax**.
            * `start` (datetime): The start of the time interval in **UTC (ISO 8601)** format. By default, it's 24 hours before the current time or the `end` time.
            * `end` (datetime): The end of the time interval in **UTC (ISO 8601)** format. By default, it's the current time.
            * `limit` (PositiveInt): The maximum number of talkers to return (default: `100`).

        * **Returns**:
            * `list[TalkersInfoMessage]`: A list of objects, each providing information about a talker. This includes the hosts' **IP address**, the **number of connections**, **first time stamp** and **latest time stamp**.

        """
        if end is None:
            end = datetime.now(timezone.utc)
        if start is None:
            start = end - timedelta(hours=24)
        return self.service.talkers(
            filter if filter else "",
            convert_datetime_to_timestamp(start, True),
            convert_datetime_to_timestamp(end, True),
        )

    def version(self) -> ProductInfoMessage:
        """
        ### Version Information Endpoint

        This endpoint retrieves the current version information for **Clear NDR**. It is primarily used to check the operational status and confirm the installed version of the MCP server.

        ---

        ### Returns

        The response provides a dictionary with the following keys:
        * `product_name`: The name of the product.
        * `flavor`: The product flavor (e.g., "Enterprise" or "Community").
        * `version`: The specific version number of the software.
        """
        return ProductInfoMessage(
            name=settings.APP_SHORT_NAME,
            version=settings.SCIRIUS_VERSION,
            flavor="Community" if settings.RULESET_MIDDLEWARE == "suricata" else "Enterprise",
        )

    def mapping_info(self) -> list[dict[str, str]]:
        """
        ### Lucene Query Fields Endpoint

        This endpoint provides essential information about **common fields** to help you construct accurate Lucene queries. Use this to understand the available fields, such as IP addresses, timestamps, and other data points, to build your queries effectively.

        ---

        ### Returns

        * `list[dict]`: A list of dictionaries, with each dictionary containing information about a specific field available for Lucene queries.
        """
        return [
            {"field": "timestamp", "type": "date", "description": "The timestamp of the alert in ISO 8601 format"},
            {"field": "src_ip", "type": "ip", "description": "The source IP address of the event"},
            {"field": "dest_ip", "type": "ip", "description": "The destination IP address of the event"},
            {"field": "src_port", "type": "integer", "description": "The source port of the event"},
            {"field": "dest_port", "type": "integer", "description": "The destination port of the event"},
            {"field": "app_proto", "type": "string", "description": "The application layer protocol of the event (HTTP, DNS, TLS, etc.)"},
            {"field": "alert.signature_id", "type": "integer", "description": "The signature ID (SID) of the rule that triggered the alert event"},
            {"field": "alert.signature", "type": "string", "description": "The name of the rule that triggered the alert event"},
            {"field": "flow_id", "type": "long", "description": "The unique identifier for the flow associated with the event"},
            {"field": "event_type", "type": "string", "description": "The type of event (alert, anomaly, DNS, HTTP, etc.)"},
            {"field": "proto", "type": "string", "description": "The protocol used in the event (TCP, UDP, ICMP, etc.)"},
            {"field": "http.hostname", "type": "string", "description": "The hostname from HTTP traffic"},
            {"field": "http.url", "type": "string", "description": "The URL from HTTP traffic"},
            {"field": "dns.query.rrname", "type": "string", "description": "The DNS resource record name"},
            {"field": "tls.sni", "type": "string", "description": "The Server Name Indication from TLS traffic"},
        ]

    @has_group_permission(required_groups=["rules.source_view"])
    def rules_search(
        self,
        query: str,
        # pagination parameters
        page: PositiveInt = 1,
        limit: PositiveInt = 50,
    ) -> list[MatchedRuleMessage]:
        """
        ### List signatures matching a query

        This endpoint retrieves a paginated list of **Intrusion Detection System rules** that match a specified search query. It allows users to search for specific detection signatures based on keywords or patterns. This is instrumental for coverage analysis and identifying rules that can detect specific threats or network behaviors.

        ### Parameters & Returns

        * **Args**:
            * `query` (str): text to search via substring matching in the rule content.
            * `page` (PositiveInt): The page number for the results (default: `1`).
            * `limit` (PositiveInt): The maximum number of events per page (default: `50`).

        * **Returns**:
            * `list[MatchedRuleMessage]`: A list of dictionaries, with each dictionary representing a Rule. The `sid` field in the result corresponds to the `SID` field in the Suricata rule.
        """
        return self.service.rules_search(
            query=query,
            page=page,
            limit=limit,
        )
