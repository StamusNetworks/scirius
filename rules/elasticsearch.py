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
from time import time
import re

URL = "http://%s/%s/_search?ignore_unavailable=true"

ALERT_ID_QUERY = """
{
  "facets": {
    "table": {
      "terms": {
        "field": "alert.signature_id",
        "size": {{ alerts_number }},
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
        "field": "timestamp",
        "interval": "{{ interval }}",
        "time_zone": "Europe/Berlin",
        "min_doc_count": 1
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
                "timestamp": {
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
        "interval": "{{ interval }}"
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

DASHBOARDS_QUERY_URL = "http://%s/%s/dashboard/_search?size=" % (settings.ELASTICSEARCH_ADDRESS, settings.KIBANA_INDEX)

HEALTH_URL = "http://%s/_cluster/health" % settings.ELASTICSEARCH_ADDRESS
STATS_URL = "http://%s/_cluster/stats" % settings.ELASTICSEARCH_ADDRESS

INDICES_STATS_URL = "http://%s/_stats/docs" % settings.ELASTICSEARCH_ADDRESS

DELETE_ALERTS_URL = "http://%s/%s/_query?q=alert.signature_id:%d"

from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables

def build_es_timestamping(date):
    format_table = { 'daily': '%Y.%m.%d', 'hourly': '%Y.%m.%d.%H' }
    now = datetime.now()
    try:
        indexes = []
        while date < now:
            indexes.append("%s%s" % (settings.ELASTICSEARCH_LOGSTASH_INDEX, date.strftime(format_table[settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING])))
            if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
                date += timedelta(days=1)
            elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
                date += timedelta(hours=1)
        return ','.join(indexes)
    except:
        return settings.ELASTICSEARCH_LOGSTASH_INDEX + '*'

def get_es_url(from_date):
    if '*' in settings.ELASTICSEARCH_LOGSTASH_INDEX:
        indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX
    else:
        if from_date == 0:
            indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
        else:
            start = datetime.fromtimestamp(int(from_date)/1000)
            indexes = build_es_timestamping(start)
    return URL % (settings.ELASTICSEARCH_ADDRESS, indexes)

def es_get_rules_stats(request, hostname, count=20, from_date=0 , qfilter = None):
    templ = Template(ALERT_ID_QUERY)
    context = Context({'appliance_hostname': hostname, 'alerts_number': count, 'from_date': from_date})
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
        data = data['facets']['table']['terms']
    except:
        rules = ExtendedRuleTable([])
        tables.RequestConfig(request).configure(rules)
        return rules
    rules = []
    if data != None:
        for elt in data:
            try:
                rule = Rule.objects.get(sid=elt['term'])
            except:
                print "Can not find rule with sid " + str(elt['term'])
                continue
            rule.hits = elt['count']
            rules.append(rule)
        rules = ExtendedRuleTable(rules)
        tables.RequestConfig(request).configure(rules)
    else:
        rules = ExtendedRuleTable([])
        tables.RequestConfig(request).configure(rules)
    return rules

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
    delete_url = DELETE_ALERTS_URL % (settings.ELASTICSEARCH_ADDRESS, settings.ELASTICSEARCH_LOGSTASH_INDEX + "*", int(sid))
    r = requests.delete(delete_url)
    data = json.loads(r.text)
    return data
