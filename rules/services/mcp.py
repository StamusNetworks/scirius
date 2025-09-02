from typing import Any, ClassVar
from django.conf import settings
from django.http import HttpRequest
from pydantic import IPvAnyAddress, PositiveInt
from rest_framework.request import Request

from rules.django_repository.rule import RuleRepository
from rules.messages.mcp import AlertMessage, HitProbeMessage, HitTimelineEntryMessage, RuleMessage, RuleReferenceMessage
from rules.es_graphs import ESEventsTail, ESSigsListHits
from rules.es_query import ESPaginator
import contextlib


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
                signature_id=line["_source"]["alert"]["signature_id"],
                source_ip=line["_source"]["flow"]["src_ip"],
                destination_ip=line["_source"]["flow"]["dest_ip"],
                protocol=line["_source"]["app_proto"],
                category=line["_source"]["alert"]["category"],
                community_id=line["_source"]["community_id"],
            )
            for line in raw["hits"]["hits"]
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
        Get the alert list in the specified time interval. If outliers is set to true then only
        the alerts never seen on an IP are going to be returned.
        Args:
            start (end): timestamp in ms
            end (end): timestamp in ms
            outlier (bool): if we set the stamus_novel filter to true
        """
        request = self._prepare_alert_list_request_object(start, end, ip, page, limit)
        return self._get_alert_list_results(request)

    def rules(self, sids: list[int]) -> list[RuleMessage]:
        """
        Get rule information from the SID.

        Args:
            sids (list[int]): one or multiple SID to find
        """
        # get hits from ES
        request = HttpRequest()
        hit_results: list[dict[str, Any]] = []
        mapping = {}

        class FakeView:
            INDEXES: ClassVar[dict[str, dict[str, str]]] = {
                "alert": {"index": settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + "*", "default": "true"},
                "stamus": {"index": settings.ELASTICSEARCH_LOGSTASH_INDEX + "stamus-*", "default": "false"},
                "discovery": {"index": settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + "*", "default": "false"},
            }

        with contextlib.suppress(Exception):
            hit_results = ESSigsListHits(Request(request), view=FakeView()).get(",".join([str(sid) for sid in sids]))

        for data in hit_results:
            if (sid := data.get("key")) and sid in sids:
                mapping[sid] = {
                    "timeline": [
                        HitTimelineEntryMessage(when=entry["key_as_string"], hits=entry["doc_count"])
                        for entry in data["timeline"]["buckets"]
                    ],
                    "probes": [
                        HitProbeMessage(name=entry["key"], hits=entry["doc_count"])
                        for entry in data["probes"]["buckets"]
                    ],
                    "hits": data["doc_count"],
                }

        # get rule info and build response
        repo = RuleRepository()
        result: list[RuleMessage] = []
        for rule in repo.rules(sids, with_rule_at_version=True, with_categories=False):
            timeline: list[HitTimelineEntryMessage] = []
            probes = []
            hits = 0
            if data := mapping.get(rule.sid):
                probes = data["probes"]
                timeline = data["timeline"]
                hits = data["hits"]

            result.append(
                RuleMessage(
                    sid=rule.sid,
                    # category=rule.category.name,
                    # category_description=rule.category.descr,
                    # category_source=rule.category__source.name,
                    message=rule.msg,
                    hits=hits,
                    references=[RuleReferenceMessage(**value) for value in rule.extract_rule_references()],
                    content=rule.ruleatversion_set.order_by("-version").first().content,
                    probes=probes,
                    timeline_data=timeline,
                )
            )
        return result
