"""
Copyright(C) 2014, 2015 Stamus Networks
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

from django.template import Context, Template
from django.conf import settings
from datetime import datetime, timedelta

import urllib2
import requests
import json
from time import time, mktime
import re

URL = "http://%s/%s/_search?ignore_unavailable=true"

TOP_QUERY = """
{
  "facets": {
    "table": {
      "terms": {
        "field": "{{ field }}",
        "size": {{ count }},
        "exclude": []
      },
      "facet_filter": {
        "fquery": {
          "query": {
            "filtered": {
              "query": {
                "bool": {
                  "should": [
                    {
                      "query_string": {
                        "query": "event_type:alert AND host.raw:{{ appliance_hostname }} {{ query_filter|safe }}"
                      }
                    }
                  ]
                }
              },
              "filter": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "from": {{ from_date }},
                          "to": "now"
                        }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }
  },
  "size": 0
}
"""

if settings.ELASTICSEARCH_2X:
    TOP_QUERY = """
{
  "size": 0,
  "aggs": {
    "table": {
      "terms": {
        "field": "{{ field }}",
        "size": {{ count }},
        "order": {
          "_count": "desc"
        }
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert AND host.raw:{{ appliance_hostname }} {{ query_filter|safe }}",
          "analyze_wildcard": false
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                 "@timestamp": {
                    "from": {{ from_date }},
                    "to": "now"
                 }
              }
            }
          ]
        }
      }
    }
  }
}
    """

SID_BY_HOST_QUERY = """
{
  "facets": {
    "terms": {
      "terms": {
        "field": "host.raw",
        "size": {{ alerts_number }},
        "order": "count",
        "exclude": []
      },
      "facet_filter": {
        "fquery": {
          "query": {
            "filtered": {
              "query": {
                "bool": {
                  "should": [
                    {
                      "query_string": {
                        "query": "event_type:alert AND alert.signature_id:{{ rule_sid }}"
                      }
                    }
                  ]
                }
              },
              "filter": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "from": {{ from_date }},
                          "to": "now"
                        }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }
  },
  "size": 0
}'
"""

if settings.ELASTICSEARCH_2X:
    SID_BY_HOST_QUERY = """
{
  "size": 0,
  "aggs": {
    "host": {
      "terms": {
        "field": "host.raw",
        "size": {{ alerts_number }},
        "order": {
          "_count": "desc"
        }
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert AND alert.signature_id:{{ rule_sid }}",
          "analyze_wildcard": false
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                 "@timestamp": {
                    "from": {{ from_date }},
                    "to": "now"
                 }
              }
            }
          ]
        }
      }
    }
  }
}
    """

TIMELINE_QUERY = """
{
  "facets": {
{% for host in hosts %}
    "{{ host }}": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "{{ interval }}"
      },
      "global": true,
      "facet_filter": {
        "fquery": {
          "query": {
            "filtered": {
              "query": {
                "query_string": {
                  "query": "event_type:alert AND host.raw:{{ host }} {{ query_filter|safe }}"
                }
              },
              "filter": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "from": {{ from_date }},
                          "to": "now"
                        }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }{% if not forloop.last %},{% endif %}{% endfor %}
  },
  "size": 0
}
"""

if settings.ELASTICSEARCH_2X:
    TIMELINE_QUERY = """
{
  "size": 0,
  "aggs": {
    "date": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "{{ interval }}",
        "time_zone": "Europe/Berlin",
        "min_doc_count": 0
      },
      "aggs": {
        "host": {
          "terms": {
            "field": "host.raw",
            "size": 5,
            "order": {
              "_count": "desc"
            }
          }
        }
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert {{ query_filter|safe }}",
          "analyze_wildcard": false
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ from_date }},
                  "lte": "now",
                  "format": "epoch_millis"
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  }
}
    """

STATS_QUERY = """
{
  "facets": {
{% if hosts %}
{% for host in hosts %}
    "{{ host }}": {
      "date_histogram": {
        "key_field": "@timestamp",
        "value_field": "{{ value }}",
        "interval": "{{ interval }}",
        "min_doc_count": 0
      },
      "global": true,
      "facet_filter": {
        "fquery": {
          "query": {
            "filtered": {
              "query": {
                "query_string": {
                  "query": "host.raw:{{ host }}"
                }
              },
              "filter": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "from": {{ from_date }},
                          "to": "now"
                        }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }{% if not forloop.last %},{% endif %}{% endfor %}
  {% else %}
    "global": {
      "date_histogram": {
        "key_field": "@timestamp",
        "value_field": "{{ value }}",
        "interval": "{{ interval }}"
      },
      "global": true,
      "facet_filter": {
        "fquery": {
          "query": {
            "filtered": {
              "query": {
                "query_string": {
                  "query": "*"
                }
              },
              "filter": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "from": {{ from_date }},
                          "to": "now"
                        }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }
  {% endif %}
  },
  "size": 0
}
"""

if settings.ELASTICSEARCH_2X:
    STATS_QUERY = """
{
  "size": 0,
  "aggs": {
    "date": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "{{ interval }}",
        "time_zone": "Europe/Berlin",
        "min_doc_count": 0
      },
      "aggs": {
        "stat": {
          "avg": {
            "field": "{{ value }}"
          }
        }
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
      {% if hosts %}
          {% for host in hosts %}
          "query": "host.raw:{{ host }}",
          {% endfor %}
      {% else %}
          "query": "tags:metric",
      {% endif %}
          "analyze_wildcard": false
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                  "@timestamp": {
                    "from": {{ from_date }},
                    "to": "now"
                  }
              }
            }
          ]
        }
      }
    }
  }
}
    """

RULES_PER_CATEGORY = """
{
  "size": 0,
  "aggs": {
    "category": {
      "terms": {
        "field": "alert.category.raw",
        "size": 50,
        "order": {
          "_count": "desc"
        }
      },
      "aggs": {
        "rule": {
          "terms": {
            "field": "alert.signature_id",
            "size": 50,
            "order": {
              "_count": "desc"
            }
          }, 
          "aggs": {
            "rule_info": {
              "terms": {
                "field": "alert.signature.raw",
                "size": 1,
                "order": {
                  "_count": "desc"
                }
              }
            }
          }
        }
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert AND host.raw:{{ hosts }} {{ query_filter|safe }}",
          "analyze_wildcard": true
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ from_date }}
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  }
}
"""

ALERTS_COUNT_PER_HOST = """
{
  "size": 0,
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert AND host.raw:{{ hosts }} {{ query_filter|safe }}",
          "analyze_wildcard": true
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ from_date }}
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  },
  "aggs": {}
}
"""

ALERTS_TREND_PER_HOST = """
{
  "size": 0,
  "aggs": {
    "trend": {
      "date_range": {
        "field": "@timestamp",
        "ranges": [
          {
            "from": {{ start_date }},
            "to": {{ from_date }}
          },
          {
            "from": {{ from_date }}
          }
        ]
      }
    }
  },
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:alert AND host.raw:{{ hosts }} {{ query_filter|safe }}",
          "analyze_wildcard": true
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ start_date }}
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  }
}
"""

LATEST_STATS_ENTRY = """
{
  "size": 1,
  "sort": [
    {
      "@timestamp": {
        "order": "desc",
        "unmapped_type": "boolean"
      }
    }
  ],
  "query": {
    "filtered": {
      "query": {
        "query_string": {
          "query": "event_type:stats AND host.raw:{{ hosts }} {{ query_filter|safe }}",
          "analyze_wildcard": true
        }
      },
      "filter": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ from_date }}
                }
              }
            }
          ],
          "must_not": []
        }
      }
    }
  },
  "fields": [
    "_source"
  ],
    "fielddata_fields": [
    "@timestamp",
    "flow.start",
    "timestamp",
    "flow.end"
  ]
}
"""

DASHBOARDS_QUERY_URL = "http://%s/%s/dashboard/_search?size=" % (settings.ELASTICSEARCH_ADDRESS, settings.KIBANA_INDEX)

HEALTH_URL = "http://%s/_cluster/health" % settings.ELASTICSEARCH_ADDRESS
STATS_URL = "http://%s/_cluster/stats" % settings.ELASTICSEARCH_ADDRESS

INDICES_STATS_URL = "http://%s/_stats/docs" % settings.ELASTICSEARCH_ADDRESS

DELETE_ALERTS_URL = "http://%s/%s/_query?q=alert.signature_id:%d"

from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables

def build_es_timestamping(date, data = 'alert'):
    format_table = { 'daily': '%Y.%m.%d', 'hourly': '%Y.%m.%d.%H' }
    now = datetime.now()
    if data == 'alert':
        base_index = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
    else:
        base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX
    try:
        indexes = []
        while date < now:
            indexes.append("%s%s" % (base_index, date.strftime(format_table[settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING])))
            if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
                date += timedelta(days=1)
            elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
                date += timedelta(hours=1)
        if len(indexes) > 20:
            return base_index + '*'
        return ','.join(indexes)
    except:
        return base_index + '*'

def get_es_url(from_date, data = 'alert'):
    if (data == 'alert' and '*' in settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX) or (data != 'alert' and '*' in settings.ELASTICSEARCH_LOGSTASH_INDEX):
            if data == 'alert':
                indexes = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
            else:
                indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX
    else:
        if from_date == 0:
            if data == 'alert':
                indexes = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + "*"
            else:
                indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
        else:
            start = datetime.fromtimestamp(int(from_date)/1000)
            indexes = build_es_timestamping(start, data = data)
    return URL % (settings.ELASTICSEARCH_ADDRESS, indexes)

def es_get_rules_stats(request, hostname, count=20, from_date=0 , qfilter = None):
    templ = Template(TOP_QUERY)
    context = Context({'appliance_hostname': hostname, 'count': count, 'from_date': from_date, 'field': 'alert.signature_id'})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = re.sub('"','\\"', query_filter)
    data = templ.render(context)
    es_url = get_es_url(from_date)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if settings.ELASTICSEARCH_2X:
            data = data['aggregations']['table']['buckets']
        else:
            data = data['facets']['table']['terms']
    except:
        rules = ExtendedRuleTable([])
        tables.RequestConfig(request).configure(rules)
        return rules
    rules = []
    if data != None:
        for elt in data:
            try:
                if settings.ELASTICSEARCH_2X:
                    sid=elt['key']
                else:
                    sid=elt['term']
                rule = Rule.objects.get(sid=sid)
            except:
                print "Can not find rule with sid " + str(sid)
                continue
            if settings.ELASTICSEARCH_2X:
                rule.hits = elt['doc_count']
            else:
                rule.hits = elt['count']
            rules.append(rule)
        rules = ExtendedRuleTable(rules)
        tables.RequestConfig(request).configure(rules)
    else:
        rules = ExtendedRuleTable([])
        tables.RequestConfig(request).configure(rules)
    return rules

def es_get_field_stats(request, field, FieldTable, hostname, key='host', count=20, from_date=0 , qfilter = None):
    templ = Template(TOP_QUERY)
    context = Context({'appliance_hostname': hostname, 'count': count, 'from_date': from_date, 'field': field})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = re.sub('"','\\"', query_filter)
    data = templ.render(context)
    es_url = get_es_url(from_date)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if settings.ELASTICSEARCH_2X:
            data = data['aggregations']['table']['buckets']
        else:
            data = data['facets']['table']['terms']
    except:
        objects = FieldTable([])
        tables.RequestConfig(request).configure(objects)
        return objects
    objects = []
    if data != None:
        for elt in data:
            if settings.ELASTICSEARCH_2X:
                fstat = {key: elt['key'], 'count': elt['doc_count'] }
            else:
                fstat = {key: elt['term'], 'count': elt['count'] }
            objects.append(fstat)
        objects = FieldTable(objects)
        tables.RequestConfig(request).configure(objects)
    else:
        objects = FieldTable([])
        tables.RequestConfig(request).configure(objects)
    return objects

def es_get_sid_by_hosts(request, sid, count=20, from_date=0):
    templ = Template(SID_BY_HOST_QUERY)
    context = Context({'rule_sid': sid, 'alerts_number': count, 'from_date': from_date})
    data = templ.render(context)
    es_url = get_es_url(from_date)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if settings.ELASTICSEARCH_2X:
            data = data['aggregations']['host']['buckets']
        else:
            data = data['facets']['terms']['terms']
    except:
        return None
    stats = []
    if data != None:
        for elt in data:
            if settings.ELASTICSEARCH_2X:
                hstat = {'host': elt['key'], 'count': elt['doc_count']}
            else:
                hstat = {'host': elt['term'], 'count': elt['count']}
            stats.append(hstat)
        stats = RuleStatsTable(stats)
        tables.RequestConfig(request).configure(stats)
    else:
        return None
    return stats

def es_get_dashboard(count=20):
    req = urllib2.Request(DASHBOARDS_QUERY_URL + str(count))
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        data = data['hits']['hits']
    except:
        return None
    if data != None:
        dashboards = {}
        for elt in data:
            try:
                dashboards[elt["_id"]] = elt["_source"]["title"]
            except:
                dashboards[elt["_id"]] = elt["_id"]
                pass
        return dashboards
    return None

def es_get_timeline(from_date=0, interval=None, hosts = None, qfilter = None):
    templ = Template(TIMELINE_QUERY)
    # 100 points on graph per default
    if interval == None:
        interval = int((time() - (int(from_date) / 1000)) / 100)
    context = Context({'from_date': from_date, 'interval': str(interval) + "s", 'hosts': hosts})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = re.sub('"','\\"', query_filter)
    data = templ.render(context)
    es_url = get_es_url(from_date)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if settings.ELASTICSEARCH_2X:
            data = data['aggregations']["date"]['buckets']
            rdata = {}
            for elt in data:
                date = elt['key']
                for host in elt["host"]['buckets']:
                    if not rdata.has_key(host["key"]):
                        rdata[host["key"]] = { 'entries': [ { "time": date, "count": host["doc_count"] } ] }
                    else:
                        rdata[host["key"]]['entries'].append({ "time": date, "count": host["doc_count"] })
            data = rdata
        else:
            data = data['facets']
    except:
        return {}
    if data != {}:
        data['from_date'] = from_date
        data['interval'] = int(interval) * 1000
    return data

def es_get_metrics_timeline(from_date=0, interval=None, value = "eve.total.rate_1m", hosts = None):
    templ = Template(STATS_QUERY)
    # 100 points on graph per default
    if interval == None:
        interval = int((time() - (int(from_date)/ 1000)) / 100)
    context = Context({'from_date': from_date, 'interval': str(interval) + "s", 'value': value, 'hosts': hosts})
    data = templ.render(context)
    es_url = get_es_url(from_date, data = 'stats')
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    if hosts == None:
        hosts = ["global"]
    try:
        if settings.ELASTICSEARCH_2X:
            data = data['aggregations']["date"]['buckets']
            rdata = {}
            for elt in data:
                date = elt['key']
                if not rdata.has_key(hosts[0]):
                    rdata[hosts[0]] = { 'entries': [ { "time": date, "mean": elt["stat"]["value"] } ] }
                else:
                    rdata[hosts[0]]['entries'].append({ "time": date, "mean": elt["stat"]["value"] })
            data = rdata
        else:
            data = data['facets']
    except:
        return {}
    data['from_date'] = from_date
    data['interval'] = int(interval) * 1000
    return data

def es_get_json(uri):
    req = urllib2.Request(uri)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    return data

def es_get_health():
    return es_get_json(HEALTH_URL)

def es_get_stats():
    return es_get_json(STATS_URL)

def es_get_indices_stats():
    return es_get_json(INDICES_STATS_URL)

def es_get_indices():
    indices = es_get_json(INDICES_STATS_URL)
    indexes_array = []
    for index in indices['indices']:
        docs = indices['indices'][index]['total']['docs']
        docs['name'] = index
        indexes_array.append(docs)
    return indexes_array

def compact_tree(tree):
    cdata = []
    for category in tree:
        rules = []
        for rule in category['rule']['buckets']:
            nnode = { 'key': rule['key'], 'doc_count': rule['doc_count'], 'msg': rule['rule_info']['buckets'][0]['key'] }
            rules.append(nnode)
        data = { 'key': category['key'], 'doc_count': category['doc_count'], 'children': rules }
        cdata.append(data)
    return cdata

def es_get_rules_per_category(from_date=0, hosts = None, qfilter = None):
    templ = Template(RULES_PER_CATEGORY)
    context = Context({'from_date': from_date, 'hosts': hosts[0]})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = query_filter
    data = templ.render(context)
    es_url = get_es_url(from_date)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # clean the data: we need to compact the leaf and previous data
    if data["hits"]["total"] > 0:
        cdata = compact_tree(data["aggregations"]["category"]["buckets"])
    else:
        return None
    rdata = {}
    rdata["key"] = "categories"
    rdata["children"] = cdata
    return rdata

def es_delete_alerts_by_sid(sid):
    delete_url = DELETE_ALERTS_URL % (settings.ELASTICSEARCH_ADDRESS, settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + "*", int(sid))
    r = requests.delete(delete_url)
    data = json.loads(r.text)
    return data

def es_get_alerts_count(from_date=0, hosts = None, qfilter = None, prev = 0):
    if prev:
        templ = Template(ALERTS_TREND_PER_HOST)
    else:
        templ = Template(ALERTS_COUNT_PER_HOST)
    context = Context({'from_date': from_date, 'hosts': hosts[0]})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = query_filter
    if prev:
        # compute delta with now and from_date
        from_datetime = datetime.fromtimestamp(int(from_date)/1000)
        start_datetime = from_datetime - (datetime.now() - from_datetime)
        start_date = int(mktime(start_datetime.timetuple()) * 1000)
        context['start_date'] = start_date
        es_url = get_es_url(start_date)
    else:
        es_url = get_es_url(from_date)
    data = templ.render(context)
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except Exception, e:
        return "BAM: " + str(e)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    if prev:
        countsdata = data["aggregations"]["trend"]["buckets"]
        return {"prev_doc_count": countsdata[0]["doc_count"], "doc_count": countsdata[1]["doc_count"]}
    else:
        return {"doc_count": data["hits"]["total"] };

def es_get_latest_stats(from_date=0, hosts = None, qfilter = None):
    templ = Template(LATEST_STATS_ENTRY)
    context = Context({'from_date': from_date, 'hosts': hosts[0]})
    if qfilter != None:
        query_filter = " AND " + qfilter
        context['query_filter'] = query_filter
    data = templ.render(context)
    es_url = get_es_url(from_date, data = 'stats')
    req = urllib2.Request(es_url, data)
    try:
        out = urllib2.urlopen(req)
    except Exception, e:
        return "BAM: " + str(e)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    try:
        return data['hits']['hits'][0]['_source']
    except:
        return None
