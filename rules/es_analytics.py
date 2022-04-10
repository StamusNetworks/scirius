"""
Copyright(C) 2015-2022, Stamus Networks
Written by Markus Kont <markus@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""
from django.conf import settings

from rules.es_query import ESQuery
from rules.es_graphs import ES_TIMESTAMP, ES_KEYWORD


class ESGetUniqueFields(ESQuery):

    def _walk_properties(self, d: dict) -> list:
        tx = []
        for k, v in d.items():
            if "properties" in v:
                sub = self._walk_properties(v["properties"])
                sub = [k + "." + item for item in sub]
                tx.extend(sub)
            else:
                tx.append(k)
        return tx

    def get(self, event_type=None) -> dict:
        if self.es is None:
            return {}

        pattern = "logstash-*"
        if event_type is not None:
            pattern = "logstash-%s-*" % event_type
        resp = self.es.indices.get_mapping(index=pattern)
        fields = []
        for k in resp:
            fields.extend(self._walk_properties(d=resp[k].get("mappings", {}).get("properties", {})))
        return {
            "fields": sorted(list(set(fields)))
        }


class ESAnalyticsBaseQuery(ESQuery):
    """
    ESGraphBase is base class for graph hunting queries. Mainly to ensure that query filters
    and index patterns are consistent over different queries that graph API relies on.
    """
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX + '*'

    def _prepare_es_field(self, col: str) -> str:
        if col not in ["flow_id", "signature_id"]:
            return col + "." + ES_KEYWORD
        return col

    def _build_query(self) -> dict:
        q = {
            "bool": {
                "must": [
                    {
                        "range": {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s %s' % (self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }
                ]
            },
        }

        event_type = self.request.GET.get("event_type", None)
        if event_type is not None:
            q["bool"]["must"].append({
                "term": {
                    "event_type.keyword": {
                        "value": event_type
                    }
                }
            })
        q["bool"].update(self._es_bool_clauses())

        return q


class ESFieldUniqAgg(ESAnalyticsBaseQuery):

    def _get_field(self) -> str:
        return self.request.GET.get("field", "src_ip")

    def _get_size(self) -> int:
        return self.request.GET.get("size", 1000)

    def _get_query(self) -> dict:
        q = {
            "size": 0,
            "query": self._build_query(),
            "aggs": {
                "fields": {
                    "terms": {
                        "field": self._prepare_es_field(self._get_field()),
                        "size": self._get_size()
                    },
                },
            }
        }
        return q


class ESGraphAgg(ESAnalyticsBaseQuery):

    def get_col_src(self) -> str:
        return self.request.GET.get("col_src", "src_ip")

    def get_col_dest(self) -> str:
        return self.request.GET.get("col_dest", "dest_ip")

    def _get_size_src(self) -> int:
        return self.request.GET.get("size_src", 100)

    def _get_size_dest(self) -> int:
        return self.request.GET.get("size_dest", 100)

    def _get_event_type(self) -> str:
        return self.request.GET.get("event_type", "all")

    def _get_query(self) -> dict:
        q = {
            "size": 0,
            "query": self._build_query(),
            "aggs": {
                "col_src": {
                    "terms": {
                        "field": self._prepare_es_field(self.get_col_src()),
                        "size": self._get_size_src()
                    },
                    "aggs": {
                        "col_dest": {
                            "terms": {
                                "field": self._prepare_es_field(self.get_col_dest()),
                                "size": self._get_size_dest()
                            }
                        },
                        "cardinality_col_dest": {
                            "cardinality": {
                                "field": self._prepare_es_field(self.get_col_dest())
                            }
                        }
                    }
                },
                "cardinality_col_src": {
                    "cardinality": {
                        "field": self._prepare_es_field(self.get_col_src())
                    }
                }
            }
        }
        return q
