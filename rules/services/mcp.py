from django.conf import settings
from django.http import HttpRequest
from pydantic import IPvAnyAddress, PositiveInt
from rest_framework.request import Request

from rules.messages.mcp import AlertMessage
from rules.es_graphs import ESEventsTail
from rules.es_query import ESPaginator


class McpService:
    def _prepare_alert_list_request_object(
        self,
        start: PositiveInt,
        end: PositiveInt,
        ip: IPvAnyAddress | None = None,
        # pagination parameters
        page: PositiveInt = 1,
        limit: PositiveInt = 20,
    ) -> HttpRequest:
        request = HttpRequest()

        request.GET["ordering"] = "-timestamp"
        request.GET["from_date"] = str(start)
        request.GET["to_date"] = str(end)

        qfilter = '((NOT alert.tag:*) OR alert.tag:"relevant")'
        if ip:
            qfilter += f" AND (flow.src_ip:{ip} OR flow.dest_ip:{ip})"
        request.GET["qfilter"] = qfilter

        request.GET["alert"] = "true"
        request.GET["discovery"] = "false"
        request.GET["stamus"] = "false"

        request.GET["page_size"] = str(limit)
        request.GET["page"] = str(page)

        return request

    def _get_alert_list_results(self, request: HttpRequest) -> list[AlertMessage]:
        drf_request = Request(request)

        pagination = ESPaginator(drf_request)
        es_params = pagination.get_es_params(None)
        raw = ESEventsTail(request, f"{settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX}*").get(es_params=es_params)
        return [
            AlertMessage(
                when=line["_source"]["@timestamp"],
                method=line["_source"]["alert"]["signature"],
                source_ip=line["_source"]["flow"]["src_ip"],
                destination_ip=line["_source"]["flow"]["dest_ip"],
                protocol=line["_source"]["app_proto"],
                category=line["_source"]["alert"]["category"],
                community_id=line["_source"]["community_id"],
            ) for line in raw["hits"]["hits"]
        ]

    def alert_list(
        self,
        start: PositiveInt,
        end: PositiveInt,
        ip: IPvAnyAddress | None = None,
        # pagination parameters
        page: PositiveInt = 1,
        limit: PositiveInt = 20,
    ) -> list[AlertMessage]:
        """
        Get the alert list

        Args:
            start (end): timestamp in ms
            end (end): timestamp in ms
            outlier (bool): if we set the stamus_novel filter to true
        """
        request = self._prepare_alert_list_request_object(start, end, ip, page, limit)
        return self._get_alert_list_results(request)
