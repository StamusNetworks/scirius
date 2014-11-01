"""
Copyright(C) 2014, Stamus Networks
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

import urllib2
import json

URL = "http://%s/_all/_search?pretty" % settings.ELASTICSEARCH_ADDRESS

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
                        "query": "event_type:alert AND host:{{ appliance_hostname }}"
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

# TODO loop on host and set interval based on duration
TIMELINE_QUERY = """
{
  "facets": {
    "1": {
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
                  "query": "event_type:alert"
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

DASHBOARDS_QUERY_URL = "http://%s/kibana-int/dashboard/_search" % settings.ELASTICSEARCH_ADDRESS

from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables

def es_get_rules_stats(request, hostname, count=20, from_date=0):
    templ = Template(ALERT_ID_QUERY)
    context = Context({'appliance_hostname': hostname, 'alerts_number': count, 'from_date': from_date})
    data = templ.render(context)
    req = urllib2.Request(URL, data)
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
    req = urllib2.Request(URL, data)
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
    req = urllib2.Request(DASHBOARDS_QUERY_URL)
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
        dashboards = []
        for elt in data:
            dashboards.append(elt["_id"])
        return dashboards
    return None

def es_get_timeline(from_date=0, interval='5m'):
    templ = Template(TIMELINE_QUERY)
    context = Context({'from_date': from_date, 'interval': interval})
    data = templ.render(context)
    req = urllib2.Request(URL, data)
    try:
        out = urllib2.urlopen(req)
    except:
        return None
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        data = data['facets']['1']['entries']
    except:
        return None
    return data
