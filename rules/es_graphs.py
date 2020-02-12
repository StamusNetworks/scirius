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
from django.conf import settings
from django.template.defaultfilters import filesizeformat
from datetime import datetime

import socket
import requests
import json
from time import time, mktime
import math

from rules.es_query import ESQuery
from rules.models import get_es_address, get_es_path
from scirius.utils import merge_dict_deeply


ES_VERSION = None
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
                                "query": "event_type:alert AND {% if sid %}alert.signature_id: {{ sid }} AND{% endif %} {{ hosts_filter }} {{ query_filter }}"
                              }
                            }
                          ]
{{ bool_clauses }}
                        }
                      },
                      "filter": {
                        "bool": {
                          "must": [
                            {
                              "range": {
                                "{{ timestamp }}": {
                                  "from": {{ from_date }},
                                  "to": {{ to_date }}
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
                  "query": "event_type:alert AND {% if sid %}alert.signature_id: {{ sid }} AND{% endif %} {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
                    {
                      "range": {
                         "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
                         }
                      }
                    }
                  ]
{{ bool_clauses }}
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
                  "query": "event_type:alert AND {% if sid %}alert.signature_id: {{ sid }} AND{% endif %} {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
                    {
                      "range": {
                         "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
                         }
                      }
                    }
                  ]
{{ bool_clauses }}
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
{{ bool_clauses }}
                        }
                      },
                      "filter": {
                        "bool": {
                          "must": [
                            {
                              "range": {
                                "{{ timestamp }}": {
                                  "from": {{ from_date }},
                                  "to": {{ to_date }}
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
                         "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
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
{{ bool_clauses }}
                }
              }
        }
            """


def get_timeline_by_tags_query():
    if get_es_major_version() < 7:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
              {
                "range": {
                  "{{ timestamp }}": {
                    "gte": {{ from_date }},
                    "lte": {{ to_date }},
                    "format": "epoch_millis"
                  }
                }
              }]
    {{ bool_clauses }}
            }
          },
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "{{ timestamp }}",
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
    else:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
              {
                "range": {
                  "{{ timestamp }}": {
                    "gte": {{ from_date }},
                    "lte": {{ to_date }},
                    "format": "epoch_millis"
                  }
                }
              }]
    {{ bool_clauses }}
            }
          },
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "{{ timestamp }}",
                "fixed_interval": "{{ interval }}",
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
                "field": "{{ timestamp }}",
                "interval": "{{ interval }}"
              },
              "global": true,
              "facet_filter": {
                "fquery": {
                  "query": {
                    "filtered": {
                      "query": {
                        "query_string": {
                          "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}"
                        }
                      },
                      "filter": {
                        "bool": {
                          "must": [
                            {
                              "range": {
                                "{{ timestamp }}": {
                                  "from": {{ from_date }},
                                  "to": {{ to_date }}
                                }
                              }
                            }
                          ]
{{ bool_clauses }}
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
    elif get_es_major_version() < 7:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
                    {
                      "range": {
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }},
                          "format": "epoch_millis"
                        }
                      }
                    }
                  ]
{{ bool_clauses }}
                }
          },
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "{{ timestamp }}",
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
    else:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [ {
                "query_string": {
                  "query": "event_type:alert {{ query_filter }}",
                  "analyze_wildcard": false
                }
              },
                    {
                      "range": {
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }},
                          "format": "epoch_millis"
                        }
                      }
                    }
                  ]
{{ bool_clauses }}
                }
          },
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "{{ timestamp }}",
                "fixed_interval": "{{ interval }}",
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
                "key_field": "{{ timestamp }}",
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
                          "query": "{{ hosts_filter }} {{ query_filter }}"
                        }
                      },
                      "filter": {
                        "bool": {
                          "must": [
                            {
                              "range": {
                                "{{ timestamp }}": {
                                  "from": {{ from_date }},
                                  "to": {{ to_date }}
                                }
                              }
                            }
                          ]
{{ bool_clauses }}
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
                "key_field": "{{ timestamp }}",
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
                                "{{ timestamp }}": {
                                  "from": {{ from_date }},
                                  "to": {{ to_date }}
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
                "field": "{{ timestamp }}",
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
                          "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
                          }
                      }
                    },
                {
                "query_string": {
              {% if value|slice:":11" != 'eve_insert.' %}{# eve_insert has no host field #}
                  {# hosts_filter can't be used since metricbeat store the keyword hostname in `host` #}
                  "query": "{% for host in hosts %}host:{{ host }} {% endfor %} {{ query_filter }}",
              {% else %}
                  "query": "tags:metric",
              {% endif %}
                  "analyze_wildcard": false
                }
              }
                  ]
{{ bool_clauses }}
                }
              }
        }
            """
    elif get_es_major_version() < 7:
        return """
        {
          "size": 0,
          "aggs": {
            "date": {
              "date_histogram": {
                "field": "{{ timestamp }}",
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
                          "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
                          }
                      }
                    },
                {
                "query_string": {
              {% if value|slice:":11" != 'eve_insert.' %}{# eve_insert has no host field #}
                  {# hosts_filter can't be used since metricbeat store the keyword hostname in `host` #}
                  "query": "{% for host in hosts %}host:{{ host }} {% endfor %} {{ query_filter }}",
              {% else %}
                  "query": "tags:metric",
              {% endif %}
                  "analyze_wildcard": false
                }
              }
                  ]
{{ bool_clauses }}
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
                "field": "{{ timestamp }}",
                "fixed_interval": "{{ interval }}",
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
                          "{{ timestamp }}": {
                            "from": {{ from_date }},
                            "to": {{ to_date }}
                          }
                      }
                    },
                {
                "query_string": {
              {% if value|slice:":11" != 'eve_insert.' %}{# eve_insert has no host field #}
                  {# hosts_filter can't be used since metricbeat store the keyword hostname in `host` #}
                  "query": "{% for host in hosts %}host:{{ host }} {% endfor %} {{ query_filter }}",
              {% else %}
                  "query": "tags:metric",
              {% endif %}
                  "analyze_wildcard": false
                }
              }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}
                        }
                      }
                    },
                    { "query_string": {
                      "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                      "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    },
                    { "query_string": {
                      "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                      "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": true
                }
              }
                  ],
                  "must_not": []
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": true
                }
              }
                  ],
                  "must_not": []
{{ bool_clauses }}
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
                "field": "{{ timestamp }}",
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
                        "{{ timestamp }}": {
                          "gte": {{ start_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": true
                }
              }
                  ]
{{ bool_clauses }}
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
                "field": "{{ timestamp }}",
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
                        "{{ timestamp }}": {
                          "gte": {{ start_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                    ,{
                "query_string": {
                  "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                  "analyze_wildcard": true
                }
              }
                  ]
{{ bool_clauses }}
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
              "{{ timestamp }}": {
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                ,{
                    "query_string": {
                      "query": "event_type:stats AND {{ hosts_filter }} {{ query_filter }}",
                      "analyze_wildcard": true
                    }
                }
                  ]
{{ bool_clauses }}
            }
          }
        }
        """
    else:
        return """
        {
          "size": 2,
          "sort": [
            {
              "{{ timestamp }}": {
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }
                ,{
                    "query_string": {
                      "query": "event_type:stats AND {{ hosts_filter }} {{ query_filter }}",
                      "analyze_wildcard": true
                    }
                }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND {{ hosts_filter }} {{ query_filter }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND alert.source.net_info:* AND {{ hosts_filter }} {{ query_filter }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}

                        }
                      }
                    }, {
                      "query_string": {
                        "query": "event_type:alert AND alert.source.net_info:* AND {{ hosts_filter }} {{ query_filter }}",
                        "analyze_wildcard": true
                      }
                    }
                  ]
{{ bool_clauses }}
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
      "{{ timestamp }}": {
        "order": "desc",
        "unmapped_type": "boolean"
      }
    }
  ],
  "query": {
    "bool": {
      "must": [{
          "range": {
            "{{ timestamp }}": {
              "gte": {{ from_date }},
              "lte": {{ to_date }}

            }
          }
      }, {
        "query_string": {
          "query": "event_type:alert {{ target_only }} {{ query_filter }}",
          "analyze_wildcard": true
        }
      }]
{{ bool_clauses }}
    }
  }
}
"""


EVENTS_FROM_FLOW_ID = """
{
  "size": 100,
  "sort": [
    {
      "{{ timestamp }}": {
        "order": "desc",
        "unmapped_type": "boolean"
      }
    }
  ],
  "query": {
    "bool": {
      "must": [{
          "range": {
            "{{ timestamp }}": {
              "gte": {{ from_date }},
              "lte": {{ to_date }}

            }
          }
      }, {
        "query_string": {
          "query": "event_type:* {{ query_filter }}",
          "analyze_wildcard": true
        }
      }]
{{ bool_clauses }}
    }
  }
}
"""

SURICATA_LOGS_TAIL = """
{
  "size": 100,
  "sort": [{
    "{{ timestamp }}": {
      "order": "desc",
      "unmapped_type": "boolean"
    }
  }],
  "query": {
    "bool": {
      "must": [{
        "range": {
          "{{ timestamp }}": {
            "gte": {{ from_date }},
            "lte": {{ to_date }}

          }
        }
      }, {
        "query_string": {
          "query": "{{ hosts_filter }} AND event_type:engine"
        }
      }]
    }
  }
}
"""


def get_top_alerts():
    if get_es_major_version() < 7:
        return """
        {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "{{ timestamp }}": {
                      "gte": {{ from_date }},
                      "lte": {{ to_date }}

                    }
                  }
                }, {
                      "query_string": {
                        "query": "event_type:alert {{ query_filter }}",
                        "analyze_wildcard": true
                   }
                }
              ]
        {{ bool_clauses }}
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
                    "field": "{{ timestamp }}",
                    "interval": "{{ interval }}",
                    "min_doc_count": 0
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
                    "{{ timestamp }}": {
                      "gte": {{ from_date }},
                      "lte": {{ to_date }}

                    }
                  }
                }, {
                      "query_string": {
                        "query": "event_type:alert {{ query_filter }}",
                        "analyze_wildcard": true
                   }
                }
              ]
        {{ bool_clauses }}
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
                    "field": "{{ timestamp }}",
                    "fixed_interval": "{{ interval }}",
                    "min_doc_count": 0
                  }
                }
              }
            }
          }
        }
        """


def get_sigs_list_hits():
    if get_es_major_version() < 7:
        return """
            {
              "size": 0,
              "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}
                        }
                      }
                    }, {
                          "query_string": {
                            "query": "event_type:alert {{ query_filter }}",
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
            {{ bool_clauses }}
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
                        "field": "{{ timestamp }}",
                        "interval": "{{ interval }}",
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
    else:
        return """
            {
              "size": 0,
              "query": {
                "bool": {
                  "must": [
                    {
                      "range": {
                        "{{ timestamp }}": {
                          "gte": {{ from_date }},
                          "lte": {{ to_date }}
                        }
                      }
                    }, {
                          "query_string": {
                            "query": "event_type:alert {{ query_filter }}",
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
            {{ bool_clauses }}
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
                        "field": "{{ timestamp }}",
                        "fixed_interval": "{{ interval }}",
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
        "size": 1000,
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
            "query": "event_type:poststats {{ query_filter }}",
            "analyze_wildcard": true
          }
        },
        {
           "range": {
             "{{ timestamp }}": {
               "from": {{ from_date }},
               "to": {{ to_date }}
             }
           }
        }
      ]
{{ bool_clauses }}
    }
  }
}
"""

HEALTH_URL = "/_cluster/health"
STATS_URL = "/_cluster/stats"
INDICES_STATS_DOCS_URL = "/_stats/docs"
INDICES_STATS_SIZE_URL = "/_stats/store"
DELETE_ALERTS_URL = "/%s*/_query?q=alert.signature_id:%%d" % settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
DELETE_ALERTS_URL_V5 = "%s*/_delete_by_query" % settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX

from rules.models import Rule
from rules.tables import ExtendedRuleTable, RuleStatsTable
import django_tables2 as tables


class ESError(Exception):
    def __init__(self, msg, initial_exception=None):
        super(ESError, self).__init__(msg)
        self.initial_exception = initial_exception


class ESRulesStats(ESQuery):
    def get(self, count=20, dict_format=False):
        data = self._render_template(get_top_query(), {'count': count, 'field': 'alert.signature_id'})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)

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
            tables.RequestConfig(self.request).configure(rules)
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
            tables.RequestConfig(self.request).configure(rules)
        else:
            rules = ExtendedRuleTable([])
            tables.RequestConfig(self.request).configure(rules)
        return rules

class ESFieldStats(ESQuery):
    def get(self, sid, field, count=20, dict_format=False):
        data = self._render_template(get_top_query(), {'count': count, 'field': field, 'sid': sid})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)

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


class ESFieldStatsAsTable(ESQuery):
    def get(self, sid, field, FieldTable, count=20):
        data = ESFieldStats(self.request).get(sid, field, count=count)
        if data == []:
            objects = FieldTable([])
            tables.RequestConfig(self.request).configure(objects)
            return objects
        objects = []
        if data != None:
            for elt in data:
                if get_es_major_version() >= 2:
                    fstat = {'host': elt['key'], 'count': elt['doc_count'] }
                else:
                    fstat = {'host': elt['term'], 'count': elt['count'] }
                objects.append(fstat)
            objects = FieldTable(objects)
            tables.RequestConfig(self.request).configure(objects)
        else:
            objects = FieldTable([])
            tables.RequestConfig(self.request).configure(objects)
        return objects


class ESSidByHosts(ESQuery):
    def get(self, sid, count=20, dict_format=False):
        data = self._render_template(get_sid_by_host_query(), {'rule_sid': sid, 'alerts_number': count})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)

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
            tables.RequestConfig(self.request).configure(stats)
        else:
            return None
        return stats


class ESTimeline(ESQuery):
    def get(self, tags=False):
        # 100 points on graph per default
        if not tags:
            func = get_timeline_query()
        else:
            func = get_timeline_by_tags_query()
        data = self._render_template(func, {})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)

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
            data['from_date'] = self._from_date()
            data['interval'] = self._interval()
        return data


class ESMetricsTimeline(ESQuery):
    def get(self, value="eve.total.rate_1m"):
        # 100 points on graph per default
        data = self._render_template(get_stats_query(), {'value': value})
        index = 'metricbeat' if not value.startswith('stats.') else None
        es_url = self._get_es_url(data=index)
        data = self._urlopen(es_url, data)

        # total number of results
        hosts = self.request.GET.get('hosts')
        if hosts is None:
            hosts = ["global"]
        else:
            hosts = hosts.split(',')

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
        data['from_date'] = self._from_date()
        data['interval'] = self._interval()
        return data


class ESPoststats(ESQuery):
    def get(self, value = "poststats.rule_filter_1"):
        data = self._render_template(POSTSTATS_SUMMARY, {'filter': value})
        es_url = self._get_es_url(data='poststats')
        data = self._urlopen(es_url, data)
        return data['aggregations']['hosts']['buckets'] if 'aggregations' in data else []


class ESHealth(ESQuery):
    def get(self):
        return self._urlopen(get_es_path(HEALTH_URL))


class ESStats(ESQuery):
    def get(self):
        return self._urlopen(get_es_path(STATS_URL))


class ESVersion(ESQuery):
    def get(self):
        es_url = self.request.data.get('es_url', '')
        if es_url.endswith('/'):
            es_url = es_url[:-1]
        url = '%s%s' % (es_url, STATS_URL)
        data = self._urlopen(url)
        return data['nodes']['versions'][0]


class ESIndicesStats(ESQuery):
    def get(self):
        return self._urlopen(get_es_path(INDICES_STATS_DOCS_URL))


class ESIndices(ESQuery):
    def get(self):
        docs = self._urlopen(get_es_path(INDICES_STATS_DOCS_URL))
        size = self._urlopen(get_es_path(INDICES_STATS_SIZE_URL))
        indices = merge_dict_deeply(docs, size)
        indexes_array = []
        if indices == None:
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
            nnode = { 'key': rule['key'], 'doc_count': rule['doc_count'], 'msg': rule['rule_info']['buckets'][0]['key'] }
            rules.append(nnode)
        data = { 'key': category['key'], 'doc_count': category['doc_count'], 'children': rules }
        cdata.append(data)
    return cdata


class ESRulesPerCategory(ESQuery):
    def get(self):
        data = self._render_template(get_rules_per_category(), {})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
        # clean the data: we need to compact the leaf and previous data
        if data["hits"]["total"] > 0:
            cdata = compact_tree(data["aggregations"]["category"]["buckets"])
        else:
            return {}
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


class ESDeleteAlertsBySid(ESQuery):
    def get(self, sid):
        if get_es_major_version() <= 2:
            return es_delete_alerts_by_sid_v2(sid)
        else:
            return es_delete_alerts_by_sid_v5(sid)


class ESAlertsCount(ESQuery):
    def get(self, prev = 0):
        if prev:
            templ = get_alerts_trend_per_host()
        else:
            templ = get_alerts_count_per_host()
        context = {}
        if prev:
            # compute delta with now and from_date
            from_datetime = datetime.fromtimestamp(self._from_date() / 1000)
            start_datetime = from_datetime - (datetime.now() - from_datetime)
            start_date = mktime(start_datetime.timetuple()) * 1000
            context['start_date'] = int(start_date)
            es_url = self._get_es_url(from_date=start_date)
        else:
            es_url = self._get_es_url()
        data = self._render_template(templ, context)
        data = self._urlopen(es_url, data)
        if prev:
            try:
                countsdata = data["aggregations"]["trend"]["buckets"]
            except KeyError:
                return {"prev_doc_count": 0, "doc_count": 0}
            return {"prev_doc_count": countsdata[0]["doc_count"], "doc_count": countsdata[1]["doc_count"]}
        else:
            return {"doc_count": data["hits"]["total"] };


class ESLatestStats(ESQuery):
    def get(self):
        data = self._render_template(get_latest_stats_entry(), {})
        es_url = self._get_es_url(data='stats')
        data = self._urlopen(es_url, data)
        try:
            res = data['hits']['hits'][0]['_source']
            if len(data['hits']['hits']) > 1:
                res['previous'] = data['hits']['hits'][1]['_source']
            return res
        except (KeyError, IndexError):
            return None


class ESIppairAlerts(ESQuery):
    def get(self):
        data = self._render_template(get_ippair_alerts_count(), {})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
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


class ESIppairNetworkAlerts(ESQuery):
    def get(self):
        data = self._render_template(get_ippair_netinfo_alerts_count(), {})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
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


class ESAlertsTail(ESQuery):
    def get(self, search_target=True):
        if search_target:
            context = {'target_only': 'AND alert.target.ip:*'}
        else:
            context = {'target_only': ''}
        data = self._render_template(ALERTS_TAIL, context)
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
        return data['hits']['hits']


class ESEventsFromFlowID(ESQuery):
    def get(self):
        data = self._render_template(EVENTS_FROM_FLOW_ID, {})
        es_url = self._get_es_url(data='all')
        data = self._urlopen(es_url, data)

        res = {}
        for item in data['hits']['hits']:
            if item['_source']['event_type'].title() not in res:
                res[item['_source']['event_type'].title()] = []
            res[item['_source']['event_type'].title()].append(item['_source'])
        return res


class ESSuriLogTail(ESQuery):
    def get(self):
        context = {'hostname': settings.ELASTICSEARCH_HOSTNAME}
        data = self._render_template(SURICATA_LOGS_TAIL, context)
        es_url = self._get_es_url(data='engine')
        data = self._urlopen(es_url, data)
        data = data['hits']['hits']
        data.reverse()
        return data


class ESTopRules(ESQuery):
    def get(self, count=20, order="desc"):
        data = self._render_template(get_top_alerts(), {'count': count, 'order': order})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
        try:
            return data['aggregations']['alerts']['buckets']
        except:
            return[]


class ESSigsListHits(ESQuery):
    def get(self, sids, order="desc"):
        count = len(sids.split(','))
        data = self._render_template(get_sigs_list_hits(), {'sids': sids, 'count': count})
        es_url = self._get_es_url()
        data = self._urlopen(es_url, data)
        try:
            return data['aggregations']['alerts']['buckets']
        except:
            return []
