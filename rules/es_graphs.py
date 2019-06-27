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

from __future__ import unicode_literals
from django.template import Context, Template
from django.conf import settings
from django.utils.html import format_html
from datetime import datetime, timedelta

import logging
import urllib2
import socket
import requests
import json
from time import time, mktime
import re
import math

from rules.models import get_es_address, get_es_path

URL = "%s%s/_search?ignore_unavailable=true"

# ES requests timeout (keep this below Scirius's ajax requests timeout)
TIMEOUT = 30
es_logger = logging.getLogger('elasticsearch')


ES_VERSION = None
def get_es_major_version():
    global ES_VERSION
    if ES_VERSION is not None:
        return ES_VERSION[0]

    try:
        es_stats = es_get_stats()
        es_version = es_stats['nodes']['versions'][0].split('.')
    except (TypeError, ValueError, ESError):
        return 6

    ES_VERSION = [int(v) for v in es_version]
    return ES_VERSION[0]


def reset_es_version():
    global ES_VERSION
    ES_VERSION = None


def get_top_query():
    if get_es_major_version() < 2:
        return """
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
                                "query": "event_type:alert AND {{ hostname }}.{{ keyword }}:{{ appliance_hostname }} {{ query_filter|safe }}"
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
    if get_es_major_version() < 6:
        return """
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
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert AND {{ hostname }}.{{ keyword }}:{{ appliance_hostname }} {{ query_filter|safe }}",
                  "analyze_wildcard": false
                }
              },
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
            """
    else:
        return """
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
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert AND {{ hostname }}:{{ appliance_hostname }} {{ query_filter|safe }}",
                  "analyze_wildcard": false
                }
              },
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
            """

def get_sid_by_host_query():
    if get_es_major_version() < 2:
        return """
        {
          "facets": {
            "terms": {
              "terms": {
                "field": "{{ hostname }}.{{ keyword }}",
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
    else:
        return """
        {
          "size": 0,
          "aggs": {
            "host": {
              "terms": {
                "field": "{{ hostname }}.{{ keyword }}",
                "size": {{ alerts_number }},
                "order": {
                  "_count": "desc"
                }
              }
            }
          },
          "query": {
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
                    ,{
                    "query_string": {
                       "query": "event_type:alert AND alert.signature_id:{{ rule_sid }}",
                       "analyze_wildcard": false
                     }
                    }
                  ]
                }
              }
        }
            """


def get_timeline_by_tags_query():
    return """
    {
      "size": 0,
      "query": {
        "bool": {
          "must": [ {
            "query_string": {
              "query": "event_type:alert {{ query_filter|safe }}",
              "analyze_wildcard": false
            }
          },
          {
            "range": {
              "@timestamp": {
                "gte": {{ from_date }},
                "lte": "now",
                "format": "epoch_millis"
              }
            }
          }]
        }
      },
      "aggs": {
        "date": {
          "date_histogram": {
            "field": "@timestamp",
            "interval": "{{ interval }}",
            "min_doc_count": 0
          },
          "aggs": {
            "host": {
              "terms": {
                "field": "alert.tag.{{ keyword }}",
                "missing": "untagged",
                "size": 5,
                "order": {
                  "_count": "desc"
                }
              }
            }
          }
        }
      }
    }
        """


def get_timeline_query():
    if get_es_major_version() < 2:
        return """
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
                          "query": "event_type:alert AND {{ hostname }}.{{ keyword }}:{{ host }} {{ query_filter|safe }}"
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
    else:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert {{ query_filter|safe }}",
                  "analyze_wildcard": false
                }
              },
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }},
                          "lte": "now",
                          "format": "epoch_millis"
                        }
                      }
                    }
                  ]
                }
          },
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "@timestamp",
                "interval": "{{ interval }}",
                "min_doc_count": 0
              },
              "aggs": {
                "host": {
                  "terms": {
                    "field": "{{ hostname }}.{{ keyword }}",
                    "size": 5,
                    "order": {
                      "_count": "desc"
                    }
                  }
                }
              }
            }
          }
        }
            """

def get_stats_query():
    if get_es_major_version() < 2:
        return """
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
                          "query": "{{ hostname }}.{{ keyword }}:{{ host }} {{ query_filter|safe }}"
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
    elif get_es_major_version() < 6:
        return """
        {
          "size": 0,
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "@timestamp",
                "interval": "{{ interval }}",
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
                "bool": {
                  "must": [
                    {
                      "range": {
                          "@timestamp": {
                            "from": {{ from_date }},
                            "to": "now"
                          }
                      }
                    },
                {
                "query_string": {
              {% if hosts %}
                  {% for host in hosts %}
                  "query": "{{ hostname }}.{{ keyword }}:{{ host }} {{ query_filter|safe }}",
                  {% endfor %}
              {% else %}
                  "query": "tags:metric",
              {% endif %}
                  "analyze_wildcard": false
                }
              }
                  ]
                }
              }
        }
            """
    else:
        return """
        {
          "size": 0,
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "@timestamp",
                "interval": "{{ interval }}",
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
                "bool": {
                  "must": [
                    {
                      "range": {
                          "@timestamp": {
                            "from": {{ from_date }},
                            "to": "now"
                          }
                      }
                    },
                {
                "query_string": {
              {% if hosts %}
                  {% for host in hosts %}
                  "query": "{{ hostname }}:{{ host }} {{ query_filter|safe }}",
                  {% endfor %}
              {% else %}
                  "query": "tags:metric",
              {% endif %}
                  "analyze_wildcard": false
                }
              }
                  ]
                }
              }
        }
            """

def get_rules_per_category():
    if get_es_major_version() < 6:
        return """
        {
          "size": 0,
          "aggs": {
            "category": {
              "terms": {
                "field": "alert.category.{{ keyword }}",
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
                        "field": "alert.signature.{{ keyword }}",
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    },
                    { "query_string": {
                      "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                      "analyze_wildcard": true
                      }
                    }
                  ]
               }
          }
        }
        """
    else:
        return """
        {
          "size": 0,
          "aggs": {
            "category": {
              "terms": {
                "field": "alert.category.{{ keyword }}",
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
                        "field": "alert.signature.{{ keyword }}",
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    },
                    { "query_string": {
                      "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                      "analyze_wildcard": true
                      }
                    }
                  ]
               }
          }
        }
        """

def get_alerts_count_per_host():
    if get_es_major_version() < 6:
        return """
        {
          "size": 0,
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                  "analyze_wildcard": true
                }
              }
                  ],
                  "must_not": []
                }
          },
          "aggs": {}
        }
        """
    else:
        return """
        {
          "size": 0,
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                  "analyze_wildcard": true
                }
              }
                  ],
                  "must_not": []
                }
          },
          "aggs": {}
        }
        """

def get_alerts_trend_per_host():
    if get_es_major_version() < 6:
        return """
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ start_date }}
                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                  "analyze_wildcard": true
                }
              }
                  ]
                }
          }
        }
        """
    else:
        return """
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ start_date }}
                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                  "analyze_wildcard": true
                }
              }
                  ]
                }
          }
        }
        """

def get_latest_stats_entry():
    if get_es_major_version() < 6:
        return """
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }
                ,{
                    "query_string": {
                      "query": "event_type:stats AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                      "analyze_wildcard": true
                    }
                }
                  ]
            }
          }
        }
        """
    else:
        return """
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
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }
                ,{
                    "query_string": {
                      "query": "event_type:stats AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                      "analyze_wildcard": true
                    }
                }
                  ]
            }
          }
        }
        """


def get_ippair_alerts_count():
    if get_es_major_version() < 6:
        return """
        {
          "size": 0,
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
                }
              },
          "aggs": {
                "src_ip": {
                  "terms": {
                    "field": "src_ip.{{ keyword }}",
                    "size": 20,
                    "order": {
                      "_count": "desc"
                    }
                  },
                  "aggs": {
                    "dest_ip": {
                      "terms": {
                        "field": "dest_ip.{{ keyword }}",
                        "size": 20,
                        "order": {
                          "_count": "desc"
                        }
                    }, "aggs": {
                        "alerts": {
                            "terms": {
                                "field": "alert.signature.{{ keyword }}",
                                "size": 20,
                                "order": {
                                    "_count": "desc"
                                }
                            }
                        }
                     }
                   }
                }
            }
          }
        }
        """
    else:
        return """
        {
          "size": 0,
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
                }
              },
          "aggs": {
                "src_ip": {
                  "terms": {
                    "field": "src_ip",
                    "size": 20,
                    "order": {
                      "_count": "desc"
                    }
                  },
                  "aggs": {
                    "dest_ip": {
                      "terms": {
                        "field": "dest_ip",
                        "size": 20,
                        "order": {
                          "_count": "desc"
                        }
                    }, "aggs": {
                        "alerts": {
                            "terms": {
                                "field": "alert.signature.{{ keyword }}",
                                "size": 20,
                                "order": {
                                    "_count": "desc"
                                }
                            }
                        }
                     }
                   }
                }
            }
          }
        }
        """

def get_ippair_netinfo_alerts_count():
    if get_es_major_version() < 6:
        return """
        {
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND alert.source.net_info:* AND ({% for host in hosts %}{{ hostname }}.{{ keyword }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
                }
              },
                "aggs": {
                "src_ip": {
                  "terms": {
                    "field": "alert.source.ip.{{ keyword }}",
                    "size": 40,
                    "order": {
                      "_count": "desc"
                    }
                  },
                  "aggs": {
                    "net_src": {
                      "terms": {
                        "field": "alert.source.net_info_agg.{{ keyword }}",
                        "size": 1,
                        "order": {
                          "_count": "desc"
                        }
                   },
                    "aggs": {
                      "dest_ip": {
                        "terms": {
                          "field": "alert.target.ip.{{ keyword }}",
                          "size": 40,
                          "order": {
                            "_count": "desc"
                          }
                        },
                      "aggs": {
                        "net_dest": {
                          "terms": {
                            "field": "alert.target.net_info_agg.{{ keyword }}",
                            "size": 1,
                            "order": {
                              "_count": "desc"
                            }
                          },
                          "aggs": {
                            "alerts": {
                                "terms": {
                                "field": "alert.signature.{{ keyword }}",
                                "size": 20,
                                "order": {
                                    "_count": "desc"
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
        """
    else:
        return """
        {
          "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "@timestamp": {
                          "gte": {{ from_date }}
                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND alert.source.net_info:* AND ({% for host in hosts %}{{ hostname }}:{{ host }} {% endfor %}) {{ query_filter|safe }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
                }
              },
                "aggs": {
                "src_ip": {
                  "terms": {
                    "field": "alert.source.ip.{{ keyword }}",
                    "size": 40,
                    "order": {
                      "_count": "desc"
                    }
                  },
                  "aggs": {
                    "net_src": {
                      "terms": {
                        "field": "alert.source.net_info_agg.{{ keyword }}",
                        "size": 1,
                        "order": {
                          "_count": "desc"
                        }
                   },
                    "aggs": {
                      "dest_ip": {
                        "terms": {
                          "field": "alert.target.ip.{{ keyword }}",
                          "size": 40,
                          "order": {
                            "_count": "desc"
                          }
                        },
                      "aggs": {
                        "net_dest": {
                          "terms": {
                            "field": "alert.target.net_info_agg.{{ keyword }}",
                            "size": 1,
                            "order": {
                              "_count": "desc"
                            }
                          },
                          "aggs": {
                            "alerts": {
                                "terms": {
                                "field": "alert.signature.{{ keyword }}",
                                "size": 20,
                                "order": {
                                    "_count": "desc"
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
        """

ALERTS_TAIL = """
{
  "size": 100,
  "sort": [
    {
      "@timestamp": {
        "order": "desc",
        "unmapped_type": "boolean"
      }
    }
  ],
  "query": {
        "bool": {
          "must": [
            {
              "range": {
                "@timestamp": {
                  "gte": {{ from_date }}
                }
              }
            }
        ,{
            "query_string": {
              "query": "event_type:alert {{ target_only }} {{ query_filter|safe }}",
              "analyze_wildcard": true
            }
        }
          ]
    }
  }
}
"""

SURICATA_LOGS_TAIL = """
{
  "size": 100,
  "sort": [{
    "@timestamp": {
      "order": "desc",
      "unmapped_type": "boolean"
    }
  }],
  "query": {
    "bool": {
      "must": [{
        "range": {
          "@timestamp": {
            "gte": {{ from_date }}
          }
        }
      }, {
        "query_string": {
      {% if hosts %}
          {% for host in hosts|slice:":-1" %}
          "query": "{{ hostname }}:{{ host }} AND event_type:engine",
          {% endfor %}
          "query": "{{ hostname }}:{{ hosts|last }} AND event_type:engine"
      {% else %}
          "query": "event_type:engine",
      {% endif %}
        }
      }]
    }
  }
}
"""


TOP_ALERTS = """
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": {{ from_date }}
            }
          }
        }, {
              "query_string": {
                "query": "event_type:alert {{ query_filter|safe }}",
                "analyze_wildcard": true
           }
        }
      ]
    }
  },
  "aggs": {
    "alerts": {
      "terms": {
        "field": "alert.signature_id",
        "size": {{ count }},
        "order": {
          "_count": "{{ order }}"
        }
      },
      "aggs": {
        "timeline": {
          "date_histogram": {
            "field": "@timestamp",
            "interval": "{{ interval }}s",
            "min_doc_count": 0
          }
        }
      }
    }
  }
}
"""

SIGS_LIST_HITS = """
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": {{ from_date }}
            }
          }
        }, {
              "query_string": {
                "query": "event_type:alert {{ query_filter|safe }}",
                "analyze_wildcard": true
           }
        } , {
            "constant_score" : {
                "filter" : {
                    "terms" : { 
                        "alert.signature_id" : [{{ sids }}]
                     }
                }
            }
        }
      ]
    }
  },
  "aggs": {
    "alerts": {
      "terms": {
        "field": "alert.signature_id",
        "size": {{ count }},
        "min_doc_count": 1
      },
      "aggs": {
        "timeline": {
          "date_histogram": {
            "field": "@timestamp",
            "interval": "{{ interval }}s",
            "min_doc_count": 0
          }
        },
        "probes": {
           "terms": {
               "field": "{{ hostname }}.{{ keyword }}",
               "size": 10,
               "min_doc_count": 1
           }
        }
      }
    }
  }
}
"""

POSTSTATS_SUMMARY = """
{
  "size": 0,
  "aggs": {
    "hosts": {
      "terms": {
        "field": "host.keyword",
        "size": 5,
        "order": {
          "_term": "desc"
        }
      },
      "aggs": {
        "seen": {
          "sum": {
            "field": "poststats.{{ filter }}.seen_delta"
          }
        },
        "drop": {
          "sum": {
            "field": "poststats.{{ filter }}.drop_delta"
          }
        }
      }
    }
  },
  "version": true,
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "event_type:poststats {{ query_filter|safe }}",
            "analyze_wildcard": true
          }
        },
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
"""

HEALTH_URL = "/_cluster/health"
STATS_URL = "/_cluster/stats"
INDICES_STATS_URL = "/_stats/docs"
DELETE_ALERTS_URL = "/%s*/_query?q=alert.signature_id:%%d" % settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
DELETE_ALERTS_URL_V5 = "%s*/_delete_by_query" % settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX

from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables


class ESError(Exception):
    pass


def _urlopen(request):
    try:
        out = urllib2.urlopen(request, timeout=TIMEOUT)
    except (urllib2.URLError, socket.timeout) as e:
        msg = unicode(e)
        es_logger.exception(msg)
        raise ESError(msg)
    return out


def build_es_timestamping(date, data = 'alert'):
    format_table = { 'daily': '%Y.%m.%d', 'hourly': '%Y.%m.%d.%H' }
    now = datetime.now()
    if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
        end = now + timedelta(days=1)
    elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
        end = now + timedelta(hours=1)
    if data == 'alert':
        base_index = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
    elif data == 'host_id':
        base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'host_id-'
    else:
        base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX
    try:
        indexes = []
        while date < end:
            indexes.append("%s%s*" % (base_index, date.strftime(format_table[settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING])))
            if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
                date += timedelta(days=1)
            elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
                date += timedelta(hours=1)
        if len(indexes) > 20:
            return base_index + '2*'
        return ','.join(indexes)
    except:
        return base_index + '2*'

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
            elif data == 'host_id':
                indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "host_id-*"
            else:
                indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
        else:
            start = datetime.fromtimestamp(int(from_date)/1000)
            indexes = build_es_timestamping(start, data = data)
    return URL % (get_es_address(), indexes)

def render_template(tmpl, dictionary, qfilter = None):
    if dictionary.get('hosts'):
        hosts = []
        for host in dictionary['hosts']:
            if host != '*':
                host = format_html('\\"{}\\"', host)
            hosts.append(host)
        dictionary['hosts'] = hosts

    templ = Template(tmpl)
    context = Context(dictionary)
    if qfilter != None:
        query_filter = " AND " + qfilter
        # dump as json but remove quotes since the quotes are already set in templates
        context['query_filter'] = json.dumps(query_filter)[1:-1]
    context['keyword'] = settings.ELASTICSEARCH_KEYWORD
    context['hostname'] = settings.ELASTICSEARCH_HOSTNAME
    return bytearray(templ.render(context), encoding="utf-8")

def es_get_rules_stats(request, hostname, count=20, from_date=0 , qfilter = None, dict_format=False):
    data = render_template(get_top_query(), {'appliance_hostname': hostname, 'count': count, 'from_date': from_date, 'field': 'alert.signature_id'}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if get_es_major_version() >= 2:
            data = data['aggregations']['table']['buckets']
        else:
            data = data['facets']['table']['terms']
    except:
        if dict_format:
            return []

        rules = ExtendedRuleTable([])
        tables.RequestConfig(request).configure(rules)
        return rules

    if dict_format:
        return data if data is not None else []

    rules = []
    if data != None:
        for elt in data:
            try:
                if get_es_major_version() >= 2:
                    sid=elt['key']
                else:
                    sid=elt['term']
                rule = Rule.objects.get(sid=sid)
            except:
                print "Can not find rule with sid %s" % sid
                continue
            if get_es_major_version() >= 2:
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

def es_get_field_stats(request, field, hostname, key='host', count=20, from_date=0 , qfilter = None, dict_format=False):
    data = render_template(get_top_query(), {'appliance_hostname': hostname, 'count': count, 'from_date': from_date, 'field': field}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if get_es_major_version() >= 2:
            data = data['aggregations']['table']['buckets']
        else:
            data = data['facets']['table']['terms']
    except:
        if dict_format:
            return []
        return None

    if dict_format:
        return data if data is not None else []

    return data


def es_get_field_stats_as_table(request, field, FieldTable, hostname, key='host', count=20, from_date=0 , qfilter = None):
    data = es_get_field_stats(request, field, hostname,
                              key=key, count=count, from_date=from_date, qfilter=qfilter)
    if data == None:
        objects = FieldTable([])
        tables.RequestConfig(request).configure(objects)
        return objects
    objects = []
    if data != None:
        for elt in data:
            if get_es_major_version() >= 2:
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


def es_get_sid_by_hosts(request, sid, count=20, from_date=0, dict_format=False):
    data = render_template(get_sid_by_host_query(), {'rule_sid': sid, 'alerts_number': count, 'from_date': from_date})
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if get_es_major_version() >= 2:
            data = data['aggregations']['host']['buckets']
        else:
            data = data['facets']['terms']['terms']
    except:
        return None

    if dict_format:
        return data if data is not None else []

    stats = []
    if data != None:
        for elt in data:
            if get_es_major_version() >= 2:
                hstat = {'host': elt['key'], 'count': elt['doc_count']}
            else:
                hstat = {'host': elt['term'], 'count': elt['count']}
            stats.append(hstat)
        stats = RuleStatsTable(stats)
        tables.RequestConfig(request).configure(stats)
    else:
        return None
    return stats


def es_get_timeline(from_date=0, interval=None, hosts = None, qfilter = None, tags=False):
    # 100 points on graph per default
    if interval == None:
        interval = int((time() - (int(from_date) / 1000)) / 100)

    if not tags:
        func = get_timeline_query()
    else:
        func = get_timeline_by_tags_query()
    data = render_template(func, {'from_date': from_date, 'interval': unicode(interval) + "s", 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    try:
        if get_es_major_version() >= 2:
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

def es_get_metrics_timeline(from_date=0, interval=None, value = "eve.total.rate_1m", hosts = None, qfilter = None):
    # 100 points on graph per default
    if interval == None:
        interval = int((time() - (int(from_date)/ 1000)) / 100)
    data = render_template(get_stats_query(), {'from_date': from_date, 'interval': unicode(interval) + "s", 'value': value, 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date, data = 'stats')
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    # total number of results
    if hosts == None:
        hosts = ["global"]
    try:
        if get_es_major_version() >= 2:
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

def es_get_poststats(from_date=0,  value = "poststats.rule_filter_1", hosts = None, qfilter = None):
    data = render_template(POSTSTATS_SUMMARY, {'from_date': from_date, 'filter': value, 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date, data = 'poststats')
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    return data['aggregations']['hosts']['buckets'] if 'aggregations' in data else []

def es_get_json(uri):
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(get_es_path(uri), headers = headers)
    out = _urlopen(req)
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
    if indices == None:
        return indexes_array
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
    data = render_template(get_rules_per_category(), {'from_date': from_date, 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
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

def es_delete_alerts_by_sid_v2(sid):
    delete_url = get_es_path(DELETE_ALERTS_URL) % int(sid)
    try:
        r = requests.delete(delete_url)
    except Exception, err:
        return {'msg': 'Elasticsearch error: %s' % err, 'status': 500 }
    if r.status_code == 200:
        data = json.loads(r.text)
        return data
    elif r.status_code == 400:
        return {'msg': 'Elasticsearch 2.x needs to have delete-by-plugin installed to delete alerts for a rule.', 'status': r.status_code }
    else:
        return {'msg': 'Unknown error', 'status': r.status_code }

def es_delete_alerts_by_sid_v5(sid):
    delete_url = get_es_path(DELETE_ALERTS_URL_V5)
    data = { "query": { "match": { "alert.signature_id": sid } } }
    try:
        headers = {'content-type': 'application/json'}
        r = requests.post(delete_url, data = json.dumps(data), headers=headers)
    except Exception, err:
        return {'msg': 'Elasticsearch error: %s' % err, 'status': 500 }
    if r.status_code == 200:
        data = json.loads(r.text)
        data['status'] = 200
        return data
    elif r.status_code == 400:
        return {'msg': r.text, 'status': r.status_code }
    else:
        return {'msg': 'Unknown error', 'status': r.status_code }

def es_delete_alerts_by_sid(sid):
    if get_es_major_version() <= 2:
        return es_delete_alerts_by_sid_v2(sid)
    else:
        return es_delete_alerts_by_sid_v5(sid)

def es_get_alerts_count(from_date=0, hosts = None, qfilter = None, prev = 0):
    if prev:
        templ = get_alerts_trend_per_host()
    else:
        templ = get_alerts_count_per_host()
    context = {'from_date': from_date, 'hosts': hosts}
    if prev:
        # compute delta with now and from_date
        from_datetime = datetime.fromtimestamp(int(from_date)/1000)
        start_datetime = from_datetime - (datetime.now() - from_datetime)
        start_date = int(mktime(start_datetime.timetuple()) * 1000)
        context['start_date'] = start_date
        es_url = get_es_url(start_date)
    else:
        es_url = get_es_url(from_date)
    data = render_template(templ, context, qfilter = qfilter)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    if prev:
        try:
            countsdata = data["aggregations"]["trend"]["buckets"]
        except KeyError:
            return {"prev_doc_count": 0, "doc_count": 0}
        return {"prev_doc_count": countsdata[0]["doc_count"], "doc_count": countsdata[1]["doc_count"]}
    else:
        return {"doc_count": data["hits"]["total"] };

def es_get_latest_stats(from_date=0, hosts = None, qfilter = None):
    data = render_template(get_latest_stats_entry(), {'from_date': from_date, 'hosts': hosts})
    es_url = get_es_url(from_date, data = 'stats')
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    try:
        return data['hits']['hits'][0]['_source']
    except:
        return None

def es_get_ippair_alerts(from_date=0, hosts = None, qfilter = None):
    data = render_template(get_ippair_alerts_count(), {'from_date': from_date, 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
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
    #nodes = set(nodes)
    return {'nodes': nodes, 'links': links}
    try:
        return data['hits']['hits'][0]['_source']
    except:
        return None

def es_get_ippair_network_alerts(from_date=0, hosts = None, qfilter = None):
    data = render_template(get_ippair_netinfo_alerts_count(), {'from_date': from_date, 'hosts': hosts}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
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
    #nodes = set(nodes)
    return {'nodes': nodes, 'links': links}
    try:
        return data['hits']['hits'][0]['_source']
    except:
        return None

def es_get_alerts_tail(from_date=0, qfilter = None, search_target=True):
    if search_target:
        context = {'from_date': from_date, 'target_only': 'AND alert.target.ip:*'}
    else:
        context = {'from_date': from_date, 'target_only': ''}
    data = render_template(ALERTS_TAIL, context, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)['hits']['hits']
    return data

def es_suri_log_tail(from_date, hosts):
    context = {
        'from_date': from_date,
        'hosts': hosts,
        'hostname': settings.ELASTICSEARCH_HOSTNAME
    }
    data = render_template(SURICATA_LOGS_TAIL, context)
    es_url = get_es_url(from_date, data='engine')
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)['hits']['hits']
    data.reverse()
    return data

def es_get_top_rules(request, hostname, count=20, from_date=0 , order="desc", interval=None, qfilter = None):
    if interval == None:
        interval = int((time() - (int(from_date) / 1000)) / 100)
    data = render_template(TOP_ALERTS, {'interval': interval, 'count': count, 'from_date': from_date, 'order': order}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    try:
        return data['aggregations']['alerts']['buckets']
    except:
        return[]

def es_get_sigs_list_hits(request, sids, host, from_date=0, order="desc", interval=None, qfilter = None):
    if interval == None:
        interval = int((time() - (int(from_date) / 1000)) / 100)
    count = len(sids.split(','))
    data = render_template(SIGS_LIST_HITS, {'sids': sids, 'interval': interval,'count': count, 'from_date': from_date}, qfilter = qfilter)
    es_url = get_es_url(from_date)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(es_url, data, headers = headers)
    out = _urlopen(req)
    data = out.read()
    # returned data is JSON
    data = json.loads(data)
    try:
        return data['aggregations']['alerts']['buckets']
    except:
        return []
