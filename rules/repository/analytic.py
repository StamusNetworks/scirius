from typing import Any

from django.conf import settings

from rules.constants import ES_NO_KEYWORD_FIELDS
from rules.es_graphs import ES_TIMESTAMP
from scirius.analytic import BaseSearchConnector, get_analytic_connector


class AnalyticRepository:
    def __init__(self, connector: BaseSearchConnector | None = None) -> None:
        self.connector = get_analytic_connector() if connector is None else connector

    def _build_base_query(self, start: int, end: int, lucene_filter: str = "") -> dict[str, dict[str, Any]]:
        """
        Private helper to build the common query structure for all repository methods.
        Handles time range and lucene string filtering.
        """
        # Common filters for all analytic queries
        must_clauses = [
            {
                "range": {
                    ES_TIMESTAMP: {  # Ensure this matches your ES/OS field name
                        "gte": start,
                        "lte": end,
                    }
                }
            }
        ]

        if lucene_filter:
            must_clauses.append({"query_string": {"query": lucene_filter, "analyze_wildcard": True}})

        return {"bool": {"must": must_clauses}}

    def _get_fields(self, fields: list[str]) -> list[dict[str, str]]:
        tmpl_fields: list[dict[str, str]] = []
        for field in fields:
            if field in ES_NO_KEYWORD_FIELDS:
                tmpl_fields.append({"name": field, "key": field})
            else:
                tmpl_fields.append(
                    {"name": field, "key": f"{field}.{settings.ELASTICSEARCH_KEYWORD}"}
                )
        return tmpl_fields

    def fields_stats(  # noqa: PLR0913
        self,
        indexes: str | list[str],
        fields: list[str],
        start: int,
        end: int,
        lucene_filter: str = "",
        limit: int = 10,
        bool_clause: dict | None = None,
        *,
        top: bool = True,
    ) -> dict[str, list[dict[str, Any]]]:
        query_body = self._build_base_query(start, end, lucene_filter)
        afields = self._get_fields([fields] if isinstance(fields, str) else fields)

        # Build aggregations for each requested field
        order = "desc" if top else "asc"
        aggregations = {
            field["name"]: {"terms": {"field": field["key"], "size": limit, "order": {"_count": order}}}
            for field in afields
        }

        search_payload = {
            "size": 0,  # We only want the aggregation results, not the hits
            "query": query_body,
            "aggs": aggregations,
        }
        if bool_clause is not None:
            query_body["query"]["bool"].update(bool_clause)

        response = self.connector.execute_query(index=indexes, query=search_payload)

        # Extract buckets from response
        results = {}
        aggs_results = response.get("aggregations", {})
        for field in fields:
            buckets = aggs_results.get(field, {}).get("buckets", [])
            results[field] = [{"key": b["key"], "doc_count": b["doc_count"]} for b in buckets]

        return results
