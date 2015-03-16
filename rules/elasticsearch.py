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
import json
from time import time

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
                        "query": "event_type:alert AND host.raw:{{ appliance_hostname }}"
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
                  "query": "event_type:alert AND host.raw:{{ host }} {{ query_filter }}"
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
          "query": "event_type:alert AND host.raw:{{ hosts }} {{ query_filter }}",
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

DASHBOARDS_QUERY_URL = "http://%s/kibana-int/dashboard/_search?size=" % settings.ELASTICSEARCH_ADDRESS

HEALTH_URL = "http://%s/_cluster/health" % settings.ELASTICSEARCH_ADDRESS

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
        print indexes
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

def es_get_rules_stats(request, hostname, count=20, from_date=0):
    templ = Template(ALERT_ID_QUERY)
    context = Context({'appliance_hostname': hostname, 'alerts_number': count, 'from_date': from_date})
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
        return None
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
        return None
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
        data = data['facets']['terms']['terms']
    except:
        return None
    stats = []
    if data != None:
        for elt in data:
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
    # total number of results
    try:
        data = data['facets']
    except:
        return None
    data['from_date'] = from_date
    data['interval'] = int(interval) * 1000
    return data

def es_get_health():
    req = urllib2.Request(HEALTH_URL)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    return data

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
    hosts="ice-age2"
    context = Context({'from_date': from_date, 'hosts': hosts})
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
    cdata = compact_tree(data["aggregations"]["category"]["buckets"])
    rdata = {}
    rdata["key"] = "categories"
    rdata["children"] = cdata
    return rdata
