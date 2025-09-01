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

    @has_group_permission(required_groups=['rules.events_view'])
    def alert_list(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        ip: IPvAnyAddress | None = None,
        # pagination parameters
        page: PositiveInt = 1,
        limit: PositiveInt = 50,
    ) -> list[AlertMessage]:
        """
        Get list of IDS alerts in the specified time interval. If outliers is set to true then only the alerts never seen on an IP are going to be returned. The outliers params at true allows to detect anomalies.

        Args:
            start (datetime): start date of the interval in UTC format (ISO 8601), by default it is 24h before the current time or the end time
            end (datetime | None): end date of the interval in UTC (ISO 8601), by default it is the current time
            ip (str | None): IPv4 or IPv6 if you want to filter on specific hosts
            page (PositiveInt): The page number for pagination. Defaults to 1.
            limit (PositiveInt): The maximum number of alerts to return per page. Defaults to 50.
        """
        if end is None:
            end = datetime.now(timezone.utc)
        if start is None:
            start = end - timedelta(hours=24)

        return self.service.alert_list(
            convert_datetime_to_timestamp(start, True),
            convert_datetime_to_timestamp(end, True),
            ip,
            page,
            limit,
        )

    @has_group_permission(required_groups=['rules.ruleset_policy_view'])
    def rules(self, sid: PositiveInt | list[PositiveInt]) -> list[RuleMessage]:
        """
        Get rule information from the SID (signature ID)

        Args:
            ip (int | list[int]): one or multiple SID to find
        """
        return self.service.rules([sid] if isinstance(sid, int) else sid)

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
