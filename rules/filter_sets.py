from __future__ import unicode_literals

FILTER_SETS = [
    {
        'content': [
            {
                'value': 1,
                'label': 'Hits min: 1',
                'fullString': True,
                'query': 'rest',
                'negated': False,
                'id': 'hits_min'
            },
            {
                'value': 10,
                'label': 'Hits max: 10',
                'fullString': True,
                'query': 'rest',
                'negated': False,
                'id': 'hits_max'
            }
        ],
        'name': 'Hunt: Low noise signature events',
        'page': 'RULES_LIST',
        'description': 'Low noise signature alerts sometimes hide the path to good artifacts and discoveries.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'TROJAN',
                'label': 'Message: TROJAN',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: Trojan related events',
        'page': 'DASHBOARDS',
        'description': 'This filter set results in Trojan related rules events being displayed.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'MALWARE',
                'label': 'Message: MALWARE',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: Malware related events',
        'page': 'DASHBOARDS',
        'description': 'This filter set results in displaying Malware related rules events',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'Executable',
                'label': 'Message: Executable',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: Executable related events',
        'page': 'DASHBOARDS',
        'description': 'This filter provides for Executable related events being displayed. Downloads/Posts and similar. It is usually interesting and advisable to investigate the results.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'Executable',
                'label': 'Message: Executable',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            },
            {
                'value': 'http',
                'label': 'app_proto: http',
                'fullString': False,
                'query': 'filter_host_id',
                'negated': False,
                'id': 'app_proto'
            },
        ],
        'name': 'Hunt: HTTP Executable related events',
        'page': 'DASHBOARDS',
        'description': 'This filter set provides results for any related events that are done via HTTP and either are posting or downloading executables.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'post',
                'label': 'http.http_method: post',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'http.http_method'
            }
        ],
        'name': 'Hunt: HTTP POSTs',
        'page': 'DASHBOARDS',
        'description': 'Displays events on HTTP POST requests. Those requests can hide malicious activity',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'firefox*',
                'label': 'http.http_user_agent: firefox*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'explorer*',
                'label': 'http.http_user_agent: explorer*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'opera*',
                'label': 'http.http_user_agent: opera*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'edge*',
                'label': 'http.http_user_agent: edge*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'wget*',
                'label': 'http.http_user_agent: wget*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'curl*',
                'label': 'http.http_user_agent: curl*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'perl*',
                'label': 'http.http_user_agent: perl*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'python*',
                'label': 'http.http_user_agent: python*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'http',
                'label': 'app_proto: http',
                'full_string': True,
                'query': 'filter',
                'negated': False,
                'id': 'app_proto'
            }
        ],
        'name': 'Hunt: Suspicious HTTP User Agents',
        'page': 'DASHBOARDS',
        'description': 'The filter set returns events that have HTTP user agents that are not usually seen too much. Hence making it a good candidate for further investigations.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'CURRENT_EVENTS',
                'label': 'msg: CURRENT_EVENTS',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: Current events',
        'page': 'DASHBOARDS',
        'description': 'This filter set provides results based on events/alerts from the CURRENT_EVENTS ET rules',
        'share': 'static'
    },
    {
        'content': [
            {
                'negated': False,
                'fullString': False,
                'id': 'dns.query.rrname',
                'value': '*',
                'label': 'dns.query.rrname: *'
            }
        ],
        'name': 'Hunt: DNS related events',
        'page': 'DASHBOARDS',
        'description': 'This filter set provides results for available DNS related metadata events.',
        'share': 'static'
    },
    {
        'content': [
            {
                'negated': False,
                'fullString': True,
                'id': 'alert.severity',
                'value': 1,
                'label': 'alert.severity: 1'
            }
        ],
        'name': 'Hunt: Severity 1 events',
        'page': 'DASHBOARDS',
        'description': 'Basic Severity 1 classified events by the rulesets.',
        'share': 'static'
    },
    {
        'content': [
            {
                'negated': True,
                'fullString': False,
                'id': 'ssh.client.software_version',
                'value': '*ssh*',
                'label': 'ssh.client.software_version: *ssh*'
            },
            {
                'value': 'ssh',
                'label': 'app_proto: ssh',
                'fullString': False,
                'query': 'filter_host_id',
                'negated': False,
                'id': 'app_proto'
            }
        ],
        'name': 'Hunt: Non lib/open ssh clients',
        'page': 'DASHBOARDS',
        'description': 'This filter results in providing events that are SSH based but have no libssh or openssh client version. Usually good starting point for further investigations.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'firefox*',
                'label': 'http.http_user_agent: firefox*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'explorer*',
                'label': 'http.http_user_agent: explorer*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'opera*',
                'label': 'http.http_user_agent: opera*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'edge*',
                'label': 'http.http_user_agent: edge*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'wget*',
                'label': 'http.http_user_agent: wget*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'curl*',
                'label': 'http.http_user_agent: curl*',
                'full_string': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'http',
                'label': 'app_proto: http',
                'full_string': True,
                'query': 'filter',
                'negated': False,
                'id': 'app_proto'
            }
        ],
        'share': 'static',
        'name': 'Not common user agents',
        'page': 'ALERTS_LIST'
    },
        {
        'content': [
            {
                'value': 'python*',
                'label': 'http.http_user_agent: python*',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'http.http_user_agent'
            }
        ],
        'name': 'Info: Python HTTP User Agents',
        'page': 'DASHBOARDS',
        'description': 'Informational filter: Any Python HTTP User Agents seen.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'curl*',
                'label': 'http.http_user_agent: curl*',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'http.http_user_agent'
            }
        ],
        'name': 'Info: Curl HTTP User Agents',
        'page': 'DASHBOARDS',
        'description': 'Informational filter: Any Curl HTTP User Agents seen.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'perl*',
                'label': 'http.http_user_agent: perl*',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'http.http_user_agent'
            }
        ],
        'name': 'Info: Perl HTTP User Agents',
        'page': 'DASHBOARDS',
        'description': 'Informational filter: Any Perl HTTP User Agents seen.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': 'wget*',
                'label': 'http.http_user_agent: wget*',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'http.http_user_agent'
            }
        ],
        'name': 'Info: Wget HTTP User Agents',
        'page': 'DASHBOARDS',
        'description': 'Informational filter: Any Wget HTTP User Agents seen.',
        'share': 'static'
    }
]
