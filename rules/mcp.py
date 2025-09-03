from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Iterable
from django.conf import settings
from django.http import HttpRequest
from mcp_server import MCPToolset
from pydantic import IPvAnyAddress, PositiveInt
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated

from rules.messages.mcp import (
    AlertMessage,
    ProductInfoMessage,
    RuleMessage,
    TalkersInfoMessage,
)
from rules.rest_permissions import HasGroupPermission
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
                raise PermissionDenied()

            # 2. Check group permissions
            if not HasGroupPermission.check_perms(request, self, required_groups):
                raise PermissionDenied()

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
    ) -> list[AlertMessage]:
        """
        Get list of IDS alerts in the specified time interval. If outliers is set to true
        then only the alerts never seen on an IP are going to be returned. The outliers params at
        true allows to detect anomalies.
        The signature_id field in the result corresponds to the SID field in the rule.

        Args:
            start (datetime): start date of the interval in UTC format (ISO 8601), by default it is 24h before the current time or the end time.
            end (datetime | None): end date of the interval in UTC (ISO 8601), by default it is the current time.
            ip (str | None): IPv4 or IPv6 if you want to filter on specific hosts.
            filter (str | None): Optional search filter on the Suricata events using Lucene syntax.
            raw (bool): true to return raw Suricata events that include protocol information and metadata instead of a concise representation (concise representation is returned by default). Set it to true for in depth analysis.
            page (PositiveInt): The page number for pagination. Defaults to 1.
            limit (PositiveInt): The maximum number of alerts to return per page. Defaults to 50.
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
        Get rule information from the SID (signature_id field in the alert). Content of the rule is also provided
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
        Get the talkers in the specified time interval. The filter field allows to filter the events that are going to be used to compute the talkers.
        It is using the Lucene syntax. It can also be a simple string to search in all fields. This last usage is useful to search for an IOC.

        Args:
            filter (str | None): filter to apply to events in the Lucene syntax. It can also be a simple string (like an IOC) to search in all fields.
            tenant (str | None): tenant number
            start (datetime): start date of the interval in UTC format (ISO 8601), by default it is 24h before the current time or the end time

        Returns:
            list[TalkersInfoMessage]: A list containing information about each talker, including its IP address,
                        total bytes sent and received, and number of connections.
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
        Get the version of Clear NDR.

        This endpoint can be useful to check if the MCP server is OK.

        Returns:
            Product name, flavor (Enterprise or Community) and the version.
        """
        return ProductInfoMessage(
            name=settings.APP_SHORT_NAME,
            version=settings.SCIRIUS_VERSION,
            flavor="Community" if settings.RULESET_MIDDLEWARE == "suricata" else "Enterprise",
        )

    def mapping_info(self) -> list[dict[str, str]]:
        """
        When building Lucene queries, it is important to know the field to use.
        This endpoint provides information about common fields like ip addresses,
        timestamps, etc. use the

        Returns:
            A list dictionary containing field information.
        """
        return [
            {"field": "timestamp", "type": "date", "description": "The timestamp of the alert in ISO 8601 format"},
            {"field": "src_ip", "type": "ip", "description": "The source IP address of the event"},
            {"field": "dest_ip", "type": "ip", "description": "The destination IP address of the event"},
            {"field": "src_port", "type": "integer", "description": "The source port of the event"},
            {"field": "dest_port", "type": "integer", "description": "The destination port of the event"},
            {"field": "app_proto", "type": "string", "description": "The application layer of the event (HTTP, DNS, TLS, etc.)"},
            {"field": "alert.signature_id", "type": "integer", "description": "The signature ID (SID) of the rule that triggered the alert"},
            {"field": "alert.signature", "type": "string", "description": "The name of the rule that triggered the alert"},
            {"field": "flow_id", "type": "long", "description": "The unique identifier for the flow associated with the alert"},
            {"field": "event_type", "type": "string", "description": "The type of event (alert, anomaly, DNS, HTTP, etc.)"},
            {"field": "proto", "type": "string", "description": "The protocol used in the event (TCP, UDP, ICMP, etc.)"},
            {"field": "http.hostname", "type": "string", "description": "The hostname from HTTP traffic"},
            {"field": "http.url", "type": "string", "description": "The URL from HTTP traffic"},
            {"field": "dns.query.rrname", "type": "string", "description": "The DNS resource record name"},
            {"field": "tls.sni", "type": "string", "description": "The Server Name Indication from TLS traffic"},
        ]
