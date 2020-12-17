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


def get_es_major_version():
    global ES_VERSION
    if ES_VERSION is not None:
        return ES_VERSION[0]

    try:
        es_stats = ESStats(None).get()
        es_version = es_stats['nodes']['versions'][0].split('.')
    except (TypeError, ValueError, ESError):
        return 6

    ES_VERSION = [int(v) for v in es_version]
    return ES_VERSION[0]


def reset_es_version():
    global ES_VERSION
    ES_VERSION = None


class ESError(Exception):
    def __init__(self, msg, initial_exception=None):
        super(ESError, self).__init__(msg)
        self.initial_exception = initial_exception


class ESFieldsStats(ESQuery):
    def _get_query(self, sid, fields, count):
        qfilter = 'event_type: alert AND '
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
            q['aggs'][field['name']] = {
                'terms': {
                    'field': field['key'],
                    'size': count,
                    'order': {
                        '_count': 'desc'
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


class ESFieldStats(ESQuery):
    def _get_query(self, field, count, sid=None):
        qfilter = 'event_type: alert AND '
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
                            '_count': 'desc'
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

    def get(self, sid, field, count=20, dict_format=False):
        data = super().get(field, count, sid)

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
        rules = ExtendedRuleTable(rules)
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


class ESSidByHosts(ESQuery):
    def _get_query(self, sid, count):
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
                            'query': 'event_type:alert AND alert.signature_id:%s' % sid,
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


class ESTimeline(ESQuery):
    def _get_query(self, tags=False):
        q = {
            'size': 0,
            'query': {
                'bool': {
                    'must': [{
                        'query_string': {
                            'query': 'event_type:alert ' + self._qfilter(),
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
                        'min_doc_count': 0
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
            rdata = {}
            for elt in data:
                date = elt['key']
                for host in elt["host"]['buckets']:
                    if host["key"] not in rdata:
                        rdata[host["key"]] = {'entries': [{"time": date, "count": host["doc_count"]}]}
                    else:
                        rdata[host["key"]]['entries'].append({"time": date, "count": host["doc_count"]})
            data = rdata
        except:
            return {}
        if data != {}:
            data['from_date'] = self._from_date()
            data['interval'] = self._interval()
        return data


class ESMetricsTimeline(ESQuery):
    def __init__(self, request, value='eve.total.rate_1m'):
        super().__init__(request)
        self.value = value
        hosts = self.request.GET.get('hosts', 'global')
        self.hosts = hosts.split(',')

    def _get_index_name(self):
        if self.value.startswith('stats.'):
            return settings.ELASTICSEARCH_LOGSTASH_INDEX
        return 'metricbeat-'

    def _get_query(self):
        if self.value.startswith('eve_insert.'):
            query = 'tags:metric'
        else:
            query = ' '.join(['host:%s' % h for h in self.hosts])
            query += self._qfilter()

        q = {
            'size': 0,
            'aggs': {
                'date': {
                    'date_histogram': {
                        'field': ES_TIMESTAMP,
                        self._es_interval_kw(): self._es_interval(),
                        'min_doc_count': 0
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

    def get(self):
        data = super().get()

        # total number of results
        try:
            data = data['aggregations']['date']['buckets']
            rdata = {}
            for elt in data:
                date = elt['key']
                if self.hosts[0] not in rdata:
                    rdata[self.hosts[0]] = {'entries': [{'time': date, 'mean': elt['stat']['value']}]}
                else:
                    rdata[self.hosts[0]]['entries'].append({'time': date, 'mean': elt['stat']['value']})
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
        return self.es.cluster.health()


class ESStats(ESQuery):
    def get(self):
        return self.es.cluster.stats()


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


class ESRulesPerCategory(ESQuery):
    def _get_query(self):
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
                            'query': 'event_type:alert AND %s %s' % (self._hosts(), self._qfilter()),
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
        if data["hits"]["total"] > 0:
            cdata = compact_tree(data["aggregations"]["category"]["buckets"])
        else:
            return {}
        rdata = {}
        rdata["key"] = "categories"
        rdata["children"] = cdata
        return rdata


class ESDeleteAlertsBySid(ESQuery):
    def get(self, sid):
        body = {"query": {"match": {"alert.signature_id": sid}}}
        req = self.es.delete_by_query(body=body, index='logstash-alert-*')
        return req


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


class ESAlertsTrend(ESQuery):
    def _from_date(self):
        return super()._from_date() - (super()._to_date(es_format=False) - super()._from_date())

    def _get_query(self):
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
                            'query': 'event_type:alert AND %s %s' % (self._hosts(), self._qfilter()),
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


class ESAlertsCount(ESQuery):
    def _get_query(self):
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
                            'query': 'event_type:alert AND %s %s' % (self._hosts(), self._qfilter()),
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
        return {"doc_count": data["hits"]["total"]}


class ESLatestStats(ESQuery):
    INDEX = settings.ELASTICSEARCH_LOGSTASH_INDEX

    def _get_query(self):
        size = 2
        if get_es_major_version() < 6:
            size = 1
        q = {
            'size': size,
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


class ESIppairAlerts(ESQuery):
    def _get_query(self):
        aggs_kw = ''
        if get_es_major_version() < 6:
            aggs_kw = '.' + ES_KEYWORD
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
                            'query': 'event_type:alert AND %s %s' % (self._hosts(), self._qfilter()),
                            'analyze_wildcard': True
                        }
                    }]
                }
            },
            'aggs': {
                'src_ip': {
                    'terms': {
                        'field': 'src_ip' + aggs_kw,
                        'size': 20,
                        'order': {
                            '_count': 'desc'
                        }
                    },
                    'aggs': {
                        'dest_ip': {
                            'terms': {
                                'field': 'dest_ip' + aggs_kw,
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


class ESAlertsTail(ESQuery):
    def _get_query(self, es_params, search_target=True, index='alert'):
        qfilter = 'event_type:%s' % index
        if search_target:
            qfilter += ' AND alert.target.ip:*'
        qfilter += self._qfilter()

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


class ESTopRules(ESQuery):
    def _get_query(self, count, order='desc'):
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
                            'query': 'event_type:alert ' + self._qfilter(),
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
                                'min_doc_count': 0
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
        return data['aggregations']['alerts']['buckets']


class ESSigsListHits(ESQuery):
    def _get_query(self, sids, order='desc'):
        sids = sids.split(',')
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
                            'query': 'event_type:alert ' + self._qfilter(),
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
        return data['aggregations']['alerts']['buckets']
