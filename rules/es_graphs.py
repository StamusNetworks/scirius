"""
Copyright(C) 2014-2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

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


import math
import json

from django.conf import settings

from rules.es_query import ESQuery
from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables

from scirius.utils import merge_dict_deeply


ES_VERSION = None
ES_TIMESTAMP = settings.ELASTICSEARCH_TIMESTAMP
ES_HOSTNAME = settings.ELASTICSEARCH_HOSTNAME
ES_KEYWORD = settings.ELASTICSEARCH_KEYWORD
ES_HOST_FIELD = '%s.%s' % (ES_HOSTNAME, ES_KEYWORD)


def extract_es_version(es_stats):
    es_version = es_stats['nodes']['versions'][0].split('.')
    es_version = [int(v) for v in es_version]
    return es_version


def fetch_es_version():
    es_stats = ESStats(None).get()
    es_version = extract_es_version(es_stats)
    return es_version


def get_es_major_version():
    global ES_VERSION
    if ES_VERSION is not None:
        return ES_VERSION[0]

    try:
        es_version = fetch_es_version()
    except (TypeError, ValueError, ESError):
        return 7

    ES_VERSION = es_version
    return ES_VERSION[0]


class ESError(Exception):
    def __init__(self, msg, initial_exception=None):
        super(ESError, self).__init__(msg)
        self.initial_exception = initial_exception


class ESManageMultipleESIndexes(ESQuery):
    def __init__(self, request, view=None, *args, **kwargs) -> None:
        self.request = request
        self.view = view
        super().__init__(request, *args, **kwargs)

    def _get_index(self):
        if self.view:
            return self.build_index()
        return super()._get_index()

    def get_event_type(self, default):
        if self.view:
            return self.build_event_type()
        return default

    def _is_enabled(self, value):
        return bool(value) and value.lower() not in ('false', '0')

    def build_index(self):
        indexes = set()
        for index, val in self.view.INDEXES.items():
            enable_str = self.request.query_params.get(index, val['default'])

            if self._is_enabled(enable_str):
                indexes.add(val['index'])

        return ','.join(indexes)

    def build_event_type(self):
        alert = self.request.query_params.get('alert', self.view.INDEXES['alert']['default'])
        stamus = self.request.query_params.get('stamus', self.view.INDEXES['stamus']['default'])
        discovery = self.request.query_params.get('discovery', self.view.INDEXES['discovery']['default'])

        events_type = []
        alert_enabled = self._is_enabled(alert)
        stamus_enabled = self._is_enabled(stamus)
        discovery_enabled = self._is_enabled(discovery)

        # xor
        if alert_enabled ^ discovery_enabled:
            if not alert_enabled:  # discovery enabled / alert disabled
                events_type.append('(event_type:alert AND discovery:*)')
            elif alert_enabled:  # alert enabled / discovery disabled
                events_type.append('(event_type:alert AND NOT discovery:*)')
        elif alert_enabled and discovery_enabled:
            events_type.append('event_type:alert')
        else:
            pass

        if stamus_enabled:
            events_type.append('event_type:stamus')

        type_filter = ' OR '.join(events_type)
        if len(events_type) > 1:
            type_filter = '(%s)' % type_filter

        return type_filter


class ESFieldsStats(ESManageMultipleESIndexes):
    def _get_query(self, sid, fields, count):
        qfilter = '%s AND ' % self.get_event_type(default='event_type:alert')
        if sid:
            qfilter += 'alert.signature_id:%s AND ' % sid
        qfilter += '%s %s' % (self._hosts(), self._qfilter())

        q = {
            'size': 0,
            'aggs': {},
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': qfilter,
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }]
                }
            }
        }
        for field in fields:
            # ordering is reversed to keep compatibility
            ordering = 'desc'
            if field['name'].startswith('-'):
                ordering = 'asc'
                field['name'] = field['name'][1:]
                field['key'] = field['key'][1:]

            q['aggs'][field['name']] = {
                'terms': {
                    'field': field['key'],
                    'size': count,
                    'order': {
                        '_count': ordering
                    }
                }
            }

        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, sid, fields, count=20, dict_format=False):
        data = super().get(sid, fields, count)

        # total number of results
        rdata = {}
        try:
            for field in fields:
                rdata[field['name']] = data['aggregations'][field['name']]['buckets']
        except Exception:
            rdata = None

        if dict_format:
            return rdata if rdata is not None else {}

        return rdata


class ESFieldStats(ESManageMultipleESIndexes):
    def _get_query(self, field, count, ordering, sid=None):
        qfilter = '%s AND ' % self.get_event_type(default='event_type:alert')
        if sid:
            qfilter += 'alert.signature_id:%s AND ' % sid
        qfilter += '%s %s' % (self._hosts(), self._qfilter())

        q = {
            'size': 0,
            'aggs': {
                'table': {
                    'terms': {
                        'field': field,
                        'size': count,
                        'order': {
                            '_count': ordering
                        }
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': qfilter,
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, sid, field, count=20, ordering='desc', dict_format=False):
        data = super().get(field, count, ordering, sid)

        # total number of results
        try:
            data = data['aggregations']['table']['buckets']
        except:
            data = None

        if dict_format:
            return data if data is not None else []

        return data


class ESRulesStats(ESFieldStats):
    def get(self, count=20, dict_format=False):
        data = super().get(None, 'alert.signature_id', count, dict_format=False)

        if dict_format:
            return data if data is not None else []

        rules = []
        if data is not None:
            for elt in data:
                try:
                    sid = elt['key']
                    rule = Rule.objects.get(sid=sid)
                except:
                    print("Can not find rule with sid %s" % sid)
                    continue
                rule.hits = elt['doc_count']
                rules.append(rule)
        rules = ExtendedRuleTable(rules, request=self.request)
        tables.RequestConfig(self.request).configure(rules)
        return rules


class ESFieldStatsAsTable(ESQuery):
    def get(self, sid, field, FieldTable, count=20):
        data = ESFieldStats(self.request).get(sid, field, count=count)
        objects = []
        if data is not None:
            for elt in data:
                fstat = {'host': elt['key'], 'count': elt['doc_count']}
                objects.append(fstat)
        objects = FieldTable(objects)
        tables.RequestConfig(self.request).configure(objects)
        return objects


class ESSidByHosts(ESManageMultipleESIndexes):
    def _get_query(self, sid, count):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'aggs': {
                'host': {
                    'terms': {
                        'field': ES_HOST_FIELD,
                        'size': count,
                        'order': {
                            '_count': 'desc'
                        }
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s AND alert.signature_id:%s' % (event_type, sid),
                            'analyze_wildcard': False
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, sid, count=20, dict_format=False):
        data = super().get(sid, count)

        # total number of results
        try:
            data = data['aggregations']['host']['buckets']
        except:
            return None

        if dict_format:
            return data if data is not None else []

        stats = []
        if data is not None:
            for elt in data:
                hstat = {'host': elt['key'], 'count': elt['doc_count']}
                stats.append(hstat)
            stats = RuleStatsTable(stats)
            tables.RequestConfig(self.request).configure(stats)
        else:
            return None
        return stats


class ESEventsTimeline(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX + '*'

    def _get_query(self):
        offset = self._from_date() % self._interval()
        qfilter = 'event_type:* ' + self._qfilter()

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': qfilter,
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date(),
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            },
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'offset': '+%sms' % offset,
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q


class ESIPFlowTimeline(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'flow-'

    def _get_query(self, target, ip):
        offset = self._from_date() % self._interval()
        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': 'event_type:* AND %s:%s' % (target, ip),
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date(),
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            },
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'offset': '+%sms' % offset,
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    },
                    'aggs': {
                        'tx_bytes': {
                            'sum': {
                                'field': 'flow.bytes_toserver'
                            }
                        },
                        'rx_bytes': {
                            'sum': {
                                'field': 'flow.bytes_toclient'
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q


class ESFlowTimeline(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'flow-'

    def _get_query(self):
        qfilter = 'event_type:* ' + self._qfilter()
        offset = self._from_date() % self._interval()

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': qfilter,
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date(),
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            },
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'offset': '+%sms' % offset,
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    },
                    'aggs': {
                        'tx_bytes': {
                            'sum': {
                                'field': 'flow.bytes_toserver'
                            }
                        },
                        'rx_bytes': {
                            'sum': {
                                'field': 'flow.bytes_toclient'
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q


class ESTimeline(ESManageMultipleESIndexes):
    def _get_query(self, tags=False):
        event_type = self.get_event_type(default='event_type:alert')
        offset = self._from_date() % self._interval()

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': False
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date(),
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            },
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'offset': '+%sms' % offset,
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    },
                    'aggs': {
                        'host': {
                            'terms': {
                                'size': 5,
                                'order': {
                                    '_count': 'desc'
                                }
                            }
                        }
                    }
                }
            }
        }
        if tags:
            terms_agg = {
                'field': 'alert.tag.' + ES_KEYWORD,
                'missing': 'untagged'
            }
        else:
            terms_agg = {'field': ES_HOST_FIELD}

        q['aggs']['date']['aggs']['host']['terms'].update(terms_agg)
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, *args, **kwargs):
        data = super().get(*args, **kwargs)

        # total number of results
        try:
            data = data['aggregations']["date"]['buckets']
            # build list of 'host' keys and check for others
            has_others = False
            host_keys = set()
            for elt in data:
                elt_set = set([item['key'] for item in elt.get('host', {}).get('buckets', [])])
                host_keys = host_keys.union(elt_set)
                if elt.get('host', {}).get('sum_other_doc_count', 0) > 0:
                    has_others = True
            rdata = {}
            for key in host_keys:
                rdata[key] = {'entries': []}
            if has_others:
                rdata['others'] = {'entries': []}
            for elt in data:
                date = elt['key']
                others = int(elt['host']['sum_other_doc_count'])

                if has_others:
                    rdata['others']['entries'].append({"time": date, "count": others})

                for host in elt["host"]['buckets']:
                    rdata[host["key"]]['entries'].append({"time": date, "count": host["doc_count"]})
                # Fill zero
                elt_set = set([item['key'] for item in elt.get('host', {}).get('buckets', [])])
                for key in host_keys.difference(elt_set):
                    rdata[key]['entries'].append({"time": date, "count": 0})

            data = rdata
        except:
            data = {}
        finally:
            data['from_date'] = self._from_date()
            data['to_date'] = self._to_date()
            data['interval'] = self._interval()
        return data


class ESMetricsTimeline(ESQuery):
    def __init__(self, request, value='eve.total.rate_1m'):
        super().__init__(request)
        self.value = value

    def _get_index_name(self):
        if self.value.startswith('stats.'):
            return settings.ELASTICSEARCH_LOGSTASH_INDEX
        return 'metricbeat-'

    def _get_query(self, host, *args, **kwargs):
        query = ''
        if self.value.startswith('eve_insert.'):
            query = 'tags:metric AND '

        query += '%s %s' % (self._hosts(), self._qfilter())
        query += self._qfilter()

        offset = self._from_date() % self._interval()

        q = {
            'size': 0,
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'offset': '+%sms' % offset,
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    },
                    'aggs': {
                        'stat': {
                            'avg': {
                                'field': self.value
                            }
                        }
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': query,
                            'analyze_wildcard': False
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, *args, **kwargs):
        host = kwargs.get('host')
        data = super().get(*args, **kwargs)

        # total number of results
        try:
            data = data['aggregations']['date']['buckets']
            rdata = {}
            for elt in data:
                date = elt['key']
                if host not in rdata:
                    rdata[host] = {'entries': [{'time': date, 'mean': elt['stat']['value']}]}
                else:
                    rdata[host]['entries'].append({'time': date, 'mean': elt['stat']['value']})
            data = rdata
        except:
            return {}
        data['from_date'] = self._from_date()
        data['interval'] = self._interval()
        return data


class ESPoststats(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX

    def _get_query(self, value='poststats.rule_filter_1'):
        q = {
            'size': 0,
            'aggs': {
                'hosts': {
                    'terms': {
                        'field': 'host.keyword',
                        'size': 1000,
                        'order': {
                            '_term': 'desc'
                        }
                    },
                    'aggs': {
                        'seen': {
                            'sum': {
                                'field': 'poststats.%s.seen_delta' % value
                            }
                        },
                        'drop': {
                            'sum': {
                                'field': 'poststats.%s.drop_delta' % value
                            }
                        }
                    }
                }
            },
            'version': True,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': 'event_type:poststats ' + self._qfilter(),
                            'analyze_wildcard': True
                        }
                    }, {
                        'range': {
                            ES_TIMESTAMP: {
                                'from': self._from_date(),
                                'to': self._to_date()
                            }
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, *args, **kwargs):
        data = super().get(*args, **kwargs)
        return data['aggregations']['hosts']['buckets'] if 'aggregations' in data else []


class ESHealth(ESQuery):
    def get(self):
        health = self.es.cluster.health()
        if self.is_read_only():
            health['status'] = 'red'
        return health


class ESStats(ESQuery):
    def get(self):
        stats = self.es.cluster.stats()
        stats['read_only'] = False

        if self.is_read_only():
            stats['status'] = 'red'
            stats['read_only'] = True
        return stats


class ESShardStats(ESQuery):
    def get(self):
        res = {'explains': []}
        shards = self.es.cat.shards(format='json', s='state', v=True)
        res['shards'] = self.es.cat.shards(s='state', v=True)

        for row in shards:
            if row['state'] != 'STARTED':
                body = {
                    'index': row['index'],
                    'shard': row['shard'],
                    'primary': row['prirep'] == 'p'
                }
                params = {'filter_path': 'index,node_allocation_decisions.node_name,node_allocation_decisions.deciders.*'}
                content = self.es.cluster.allocation_explain(body=body, params=params)
                res['explains'].append(json.dumps(content))
        res['explains'] = '\n'.join(res['explains'])

        return res


class ESVersion(ESQuery):
    def get(self):
        return self.es.cluster.stats()['nodes']['versions'][0]


class ESIndices(ESQuery):
    def get(self):
        docs = self.es.indices.stats(metric='docs')
        size = self.es.indices.stats(metric='store')
        indices = merge_dict_deeply(docs, size)
        indexes_array = []
        if indices is None:
            return indexes_array
        for index in indices['indices']:
            try:
                docs = indices['indices'][index]['total']['docs']
                docs['name'] = index
                docs['size'] = indices['indices'][index]['total']['store']['size_in_bytes']
            except:
                continue  # ES not ready yet
            else:
                indexes_array.append(docs)
        return indexes_array


def compact_tree(tree):
    cdata = []
    for category in tree:
        rules = []
        for rule in category['rule']['buckets']:
            nnode = {'key': rule['key'], 'doc_count': rule['doc_count'], 'msg': rule['rule_info']['buckets'][0]['key']}
            rules.append(nnode)
        data = {'key': category['key'], 'doc_count': category['doc_count'], 'children': rules}
        cdata.append(data)
    return cdata


class ESRulesPerCategory(ESManageMultipleESIndexes):
    def _get_query(self):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'aggs': {
                'category': {
                    'terms': {
                        'field': 'alert.category.' + ES_KEYWORD,
                        'size': 50,
                        'order': {
                            '_count': 'desc'
                        }
                    },
                    'aggs': {
                        'rule': {
                            'terms': {
                                'field': 'alert.signature_id',
                                'size': 50,
                                'order': {
                                    '_count': 'desc'
                                }
                            },
                            'aggs': {
                                'rule_info': {
                                    'terms': {
                                        'field': 'alert.signature.' + ES_KEYWORD,
                                        'size': 1,
                                        'order': {
                                            '_count': 'desc'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        # clean the data: we need to compact the leaf and previous data
        if self._parse_total_hits(data) > 0:
            cdata = compact_tree(data["aggregations"]["category"]["buckets"])
        else:
            return {}
        rdata = {}
        rdata["key"] = "categories"
        rdata["children"] = cdata
        return rdata


class ESDeleteAlertsBySid(ESQuery):
    def _get_query(self, sid):
        return {
            'query': {'match': {'alert.signature_id': sid}},
            'sort': [{
                ES_TIMESTAMP: {'order': 'desc', 'unmapped_type': 'boolean'},
                '_id': {'order': 'desc'}
            }]
        }

    def get(self, sid):
        return self._delete_by_search(sid)


class ESEventsCount(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX

    def _get_query(self):
        offset = self.from_date % int(self.interval * 1000)
        return {
            'size': 0,
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': '@timestamp',
                        'interval': self._interval(),
                        'min_doc_count': 0,
                        'offset': '+%sms' % offset,
                        'extended_bounds': {
                            'min': self._from_date(),
                            'max': self._to_date()
                        }
                    },
                    'aggs': {
                        'nb_events': {
                            'sum': {
                                'field': 'stats.json.events_delta'
                            }
                        }
                    }
                },
                'sum_events': {
                    'sum_bucket': {
                        'buckets_path': 'date>nb_events'
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': 'event_type:stats ' + self._qfilter(),
                        }
                    }, {
                        'range': {
                            '@timestamp': {
                                'gte': self._from_date(),
                                'lte': self._to_date(),
                                'format': 'epoch_millis'
                            }
                        }
                    }]
                }
            }
        }


class ESAlertsTrend(ESManageMultipleESIndexes):
    def _from_date(self):
        return super()._from_date() - (super()._to_date(es_format=False) - super()._from_date())

    def _get_query(self):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'aggs': {
                'trend': {
                    'date_range': {
                        'field': ES_TIMESTAMP,
                        'ranges': [{
                            'from': self._from_date(),
                            'to': super()._from_date()
                        }, {
                            'from': super()._from_date()
                        }]
                    }
                }
            },
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        try:
            countsdata = data["aggregations"]["trend"]["buckets"]
        except KeyError:
            return {"prev_doc_count": 0, "doc_count": 0}
        return {"prev_doc_count": countsdata[0]["doc_count"], "doc_count": countsdata[1]["doc_count"]}


class ESTimeRangeAllAlerts(ESManageMultipleESIndexes):
    def _get_query(self, *args, **kwargs):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }],
                    'must_not': []
                }
            },
            'aggs': {
                'max_timestamp': {
                    'max': {
                        'field': '@timestamp'
                    }
                },
                'min_timestamp': {
                    'min': {
                        'field': '@timestamp'
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        min_timestamp = int(data.get('aggregations', {}).get('min_timestamp', {}).get('value') or self._from_date())
        max_timestamp = int(data.get('aggregations', {}).get('max_timestamp', {}).get('value') or self._to_date(es_format=False))

        # extend min/max if range < 20secs to avoid
        # backtrace "[interval] must be 1 or greater for aggregation [date_histogram]"
        if max_timestamp - min_timestamp < 20000:
            min_timestamp -= 10000
            max_timestamp += 10000

        return {
            'min_timestamp': min_timestamp,
            'max_timestamp': max_timestamp
        }


class ESAlertsCount(ESManageMultipleESIndexes):
    def _get_query(self):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }],
                    'must_not': []
                }
            },
            'aggs': {}
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        return {"doc_count": self._parse_total_hits(data)}


class ESLatestStats(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX

    def _get_query(self):
        q = {
            'size': 2,
            'sort': [{
                ES_TIMESTAMP: {
                    'order': 'desc',
                    'unmapped_type': 'boolean'
                }
            }],
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': 'event_type:stats AND %s %s' % (self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        try:
            res = data['hits']['hits'][0]['_source']
            if len(data['hits']['hits']) > 1:
                res['previous'] = data['hits']['hits'][1]['_source']
            return res
        except (KeyError, IndexError):
            return None


class ESIppairAlerts(ESManageMultipleESIndexes):
    def _get_query(self):
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s AND %s %s' % (event_type, self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            },
            'aggs': {
                'src_ip': {
                    'terms': {
                        'field': 'src_ip',
                        'size': 20,
                        'order': {
                            '_count': 'desc'
                        }
                    },
                    'aggs': {
                        'dest_ip': {
                            'terms': {
                                'field': 'dest_ip',
                                'size': 20,
                                'order': {
                                    '_count': 'desc'
                                }
                            }, 'aggs': {
                                'alerts': {
                                    'terms': {
                                        'field': 'alert.signature.' + ES_KEYWORD,
                                        'size': 20,
                                        'order': {
                                            '_count': 'desc'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        raw_data = data['aggregations']['src_ip']['buckets']
        nodes = []
        ip_list = []
        links = []
        for src_ip in raw_data:
            if ':' in src_ip['key']:
                group = 6
            else:
                group = 4
            if not src_ip['key'] in ip_list:
                nodes.append({'id': src_ip['key'], 'group': group})
                ip_list.append(src_ip['key'])
            for dest_ip in src_ip['dest_ip']['buckets']:
                if not dest_ip['key'] in ip_list:
                    nodes.append({'id': dest_ip['key'], 'group': group})
                    ip_list.append(dest_ip['key'])
                links.append({'source': ip_list.index(src_ip['key']), 'target': ip_list.index(dest_ip['key']), 'value': (math.log(dest_ip['doc_count']) + 1) * 2, 'alerts': dest_ip['alerts']['buckets']})
        return {'nodes': nodes, 'links': links}


class ESIppairNetworkAlerts(ESQuery):
    def _get_query(self):
        q = {
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': 'event_type:alert AND alert.source.net_info:* AND %s %s' % (self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            },
            'aggs': {
                'src_ip': {
                    'terms': {
                        'field': 'alert.source.ip.' + ES_KEYWORD,
                        'size': 40,
                        'order': {
                            '_count': 'desc'
                        }
                    },
                    'aggs': {
                        'net_src': {
                            'terms': {
                                'field': 'alert.source.net_info_agg.' + ES_KEYWORD,
                                'size': 1,
                                'order': {
                                    '_count': 'desc'
                                }
                            },
                            'aggs': {
                                'dest_ip': {
                                    'terms': {
                                        'field': 'alert.target.ip.' + ES_KEYWORD,
                                        'size': 40,
                                        'order': {
                                            '_count': 'desc'
                                        }
                                    },
                                    'aggs': {
                                        'net_dest': {
                                            'terms': {
                                                'field': 'alert.target.net_info_agg.' + ES_KEYWORD,
                                                'size': 1,
                                                'order': {
                                                    '_count': 'desc'
                                                }
                                            },
                                            'aggs': {
                                                'alerts': {
                                                    'terms': {
                                                        'field': 'alert.signature.' + ES_KEYWORD,
                                                        'size': 20,
                                                        'order': {
                                                            '_count': 'desc'
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        raw_data = data['aggregations']['src_ip']['buckets']
        nodes = []
        ip_list = []
        links = []
        for src_ip in raw_data:
            try:
                dest_obj = src_ip['net_src']['buckets'][0]
            except:
                continue
            if not src_ip['key'] in ip_list:
                group = dest_obj['key']
                nodes.append({'id': src_ip['key'], 'group': group, 'type': 'source'})
                ip_list.append(src_ip['key'])
            else:
                for node in nodes:
                    if node['id'] == src_ip['key']:
                        node['type'] = 'source'
            for dest_ip in dest_obj['dest_ip']['buckets']:
                if not dest_ip['key'] in ip_list:
                    try:
                        group = dest_ip['net_dest']['buckets'][0]['key']
                    except:
                        continue
                    nodes.append({'id': dest_ip['key'], 'group': group, 'type': 'target'})
                    ip_list.append(dest_ip['key'])
                links.append({'source': ip_list.index(src_ip['key']), 'target': ip_list.index(dest_ip['key']), 'value': (math.log(dest_ip['doc_count']) + 1) * 2, 'alerts': dest_ip['net_dest']['buckets'][0]['alerts']['buckets']})
        return {'nodes': nodes, 'links': links}


class ESEventsTail(ESManageMultipleESIndexes):
    def __init__(self, request, index, view=None, *args, **kwargs):
        self.index = index
        super().__init__(request, view, *args, **kwargs)

    def _get_index(self):
        if self.view:
            return super()._get_index()
        return self.index

    def _get_query(self, es_params, event_type=None, ordering=False):
        qfilter = self._qfilter()
        event_type = self.get_event_type(default='event_type:%s' % event_type if event_type else '*')
        qfilter = '%s %s' % (event_type, qfilter)

        q = {
            'size': es_params['size'],
            'from': es_params['from'],
            'sort': [{
                ES_TIMESTAMP: {
                    'order': 'desc',
                    'unmapped_type': 'boolean'
                }
            }],
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': qfilter,
                            'analyze_wildcard': True
                        }
                    }]
                }
            }
        }

        if ordering:
            q['sort'] = [{
                es_params['sort_field']: {
                    'order': es_params['sort_order']
                }
            }]

        q['query']['bool'].update(self._es_bool_clauses())
        return q


class ESEventsFromFlowID(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX + '*-'

    def _get_query(self):
        q = {
            'size': 100,
            'sort': [{
                ES_TIMESTAMP: {
                    'order': 'desc',
                    'unmapped_type': 'boolean'
                }
            }],
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': 'event_type:* ' + self._qfilter(),
                            'analyze_wildcard': True
                        }
                    }]
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self):
        data = super().get()
        res = {}
        for item in data['hits']['hits']:
            if item['_source']['event_type'].title() not in res:
                res[item['_source']['event_type'].title()] = []
            res[item['_source']['event_type'].title()].append(item['_source'])
        return res


class ESSuriLogTail(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX

    def _get_query(self):
        return {
            'size': 100,
            'sort': [{
                ES_TIMESTAMP: {
                    'order': 'desc',
                    'unmapped_type': 'boolean'
                }
            }],
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': self._hosts() + ' AND event_type:engine'
                        }
                    }]
                }
            }
        }

    def get(self):
        data = super().get()
        data = data['hits']['hits']
        data.reverse()
        return data


class ESTopRules(ESManageMultipleESIndexes):
    def _get_query(self, count, order='desc'):
        event_type = self.get_event_type(default='event_type:alert')
        offset = self._from_date() % self._interval()

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s %s' % (event_type, self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            },
            'aggs': {
                'alerts': {
                    'terms': {
                        'field': 'alert.signature_id',
                        'size': count,
                        'order': {
                            '_count': order
                        }
                    },
                    'aggs': {
                        'timeline': {
                            'date_histogram': {
                                'field': ES_TIMESTAMP,
                                self._es_interval_kw(): self._es_interval(),
                                'offset': '+%sms' % offset,
                                'min_doc_count': 0,
                                'extended_bounds': {
                                    'min': self._from_date(),
                                    'max': self._to_date()
                                }
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, *args, **kwargs):
        data = super().get(*args, **kwargs)
        return data.get('aggregations', {}).get('alerts', {}).get('buckets', [])


class ESSigsListHits(ESManageMultipleESIndexes):
    def _get_query(self, sids, order='desc'):
        sids = sids.split(',')
        event_type = self.get_event_type(default='event_type:alert')

        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'range': {
                            ES_TIMESTAMP: {
                                'gte': self._from_date(),
                                'lte': self._to_date()
                            }
                        }
                    }, {
                        'query_string': {
                            'query': '%s %s' % (event_type, self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }, {
                        'constant_score': {
                            'filter': {
                                'terms': {
                                    'alert.signature_id': sids
                                }
                            }
                        }
                    }]
                }
            },
            'aggs': {
                'alerts': {
                    'terms': {
                        'field': 'alert.signature_id',
                        'size': len(sids),
                        'min_doc_count': 1
                    },
                    'aggs': {
                        'timeline': {
                            'date_histogram': {
                                'field': ES_TIMESTAMP,
                                self._es_interval_kw(): self._es_interval(),
                                'min_doc_count': 0
                            }
                        },
                        'probes': {
                            'terms': {
                                'field': ES_HOST_FIELD,
                                'size': 10,
                                'min_doc_count': 1
                            }
                        }
                    }
                }
            }
        }
        q['query']['bool'].update(self._es_bool_clauses())
        return q

    def get(self, *args, **kwargs):
        data = super().get(*args, **kwargs)
        # avoir error 500 if there is no Source added yet
        # we return empty list
        return data.get('aggregations', {}).get('alerts', {}).get('buckets', [])
