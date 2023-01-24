

FILTER_SETS = [
    {
        'content': [
            {
                'value': 1,
                'label': 'Alerts min: 1',
                'fullString': True,
                'query': 'rest',
                'negated': False,
                'id': 'hits_min'
            },
            {
                'value': 10,
                'label': 'Alerts max: 10',
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
                'value': 'HUNTING',
                'label': 'Message: HUNTING',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: HUNTING related events',
        'page': 'DASHBOARDS',
        'description': 'This filter set results in displaying specifically designed hunting related rules events',
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
        "content": [
            {
                "id": "app_proto",
                "value": "http",
                "label": "app_proto: http",
                "fullString": True,
                "negated": False
            },
            {
                "label": "es_filter: ( http.hostname.keyword: /10\\..*\\..*\\..*/ OR http.hostname.keyword: /192\\.168\\..*\\..*/ OR  http.hostname.keyword: /172\\.<16-32>\\..*\\..*/ ) AND http.hostname.keyword: /([0-9]{1,3}\\.){3}[0-9]{1,3}/",
                "id": "es_filter",
                "value": "( http.hostname.keyword: /10\\..*\\..*\\..*/ OR http.hostname.keyword: /192\\.168\\..*\\..*/ OR  http.hostname.keyword: /172\\.<16-32>\\..*\\..*/ ) AND http.hostname.keyword: /([0-9]{1,3}\\.){3}[0-9]{1,3}/",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: HTTP direct requests and replies to private IP",
        "page": "DASHBOARDS",
        "description": "HTTP requests and responses directly to internal IP not domain. This is not traditional since usually a domain name is used to reach out to the servers inside. Though might be common in Dev environments  - it could also indicate later movement.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "http",
                "label": "app_proto: http",
                "fullString": True,
                "negated": False
            },
            {
                "label": "ES Filter: ( NOT http.hostname.keyword: /10\\..*\\..*\\..*/ AND NOT http.hostname.keyword: /192\\.168\\..*\\..*/ AND NOT http.hostname.keyword: /172\\.<16-32>\\..*\\..*/ ) AND http.hostname.keyword: /([0-9]{1,3}\\.){3}[0-9]{1,3}/",
                "id": "es_filter",
                "value": "( NOT http.hostname.keyword: /10\\..*\\..*\\..*/ AND NOT http.hostname.keyword: /192\\.168\\..*\\..*/ AND NOT http.hostname.keyword: /172\\.<16-32>\\..*\\..*/ ) AND http.hostname.keyword: /([0-9]{1,3}\\.){3}[0-9]{1,3}/",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: HTTP non internal  direct IP requests and replies",
        "page": "DASHBOARDS",
        "description": "HTTP requests and responses directly by IP not domain. This is not traditional since usually a domain name is used to reach out to the servers outside (non private/internal IPs).",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "dns",
                "label": "app_proto: dns",
                "fullString": True,
                "negated": True
            },
            {
                "label": "ES Filter: payload_printable.keyword: *admin*",
                "id": "es_filter",
                "value": "payload_printable.keyword: *admin*",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: Admin payload search",
        "page": "DASHBOARDS",
        "description": "Search for Admin or Administrator in the alert events payloads.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "dns",
                "label": "app_proto: dns",
                "fullString": True,
                "negated": True
            },
            {
                "label": "es_filter: payload_printable.keyword: *root*",
                "id": "es_filter",
                "value": "payload_printable.keyword: *root*",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: Root payload search",
        "page": "DASHBOARDS",
        "description": "Search for root in the alert events payloads.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "http",
                "label": "app_proto: http",
                "fullString": True,
                "negated": False
            },
            {
                "label": "es_filter: payload_printable.keyword: *root* ",
                "id": "es_filter",
                "value": "payload_printable.keyword: *root* ",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: HTTP payloads containing root",
        "page": "DASHBOARDS",
        "description": "Hunt: HTTP payloads containing root.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "http",
                "label": "app_proto: http",
                "fullString": True,
                "negated": False
            },
            {
                "label": "es_filter: payload_printable.keyword: *admin* ",
                "id": "es_filter",
                "value": "payload_printable.keyword: *admin* ",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: HTTP payloads containing admin",
        "page": "DASHBOARDS",
        "description": "Hunt: HTTP payloads containing admin.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "tls",
                "label": "app_proto: tls",
                "fullString": True,
                "negated": False
            },
            {
                "label": "es_filter: payload_printable.keyword: *admin* OR payload_printable.keyword: *root* ",
                "id": "es_filter",
                "value": "payload_printable.keyword: *admin* OR payload_printable.keyword: *root* ",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: TLS payloads containing root or admin",
        "page": "DASHBOARDS",
        "description": "Hunt: TLS payloads containing root or admin.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "tls",
                "label": "app_proto: tls",
                "fullString": True,
                "negated": False
            },
            {
                "label": "es_filter: tls.version.keyword: TLSv1* OR tls.version.keyword: SSL* AND NOT tls.version.keyword: TLSv1.3 AND NOT tls.version.keyword: TLSv1.2",
                "id": "es_filter",
                "value": "tls.version.keyword: TLSv1* OR tls.version.keyword: SSL* AND NOT tls.version.keyword: TLSv1.3 AND NOT tls.version.keyword: TLSv1.2",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
        ],
        "name": "Hunt: Old TLS versions alert events",
        "page": "DASHBOARDS",
        "description": "Alert events with old or retired TLS versions.",
        "share": "static"
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
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'explorer*',
                'label': 'http.http_user_agent: explorer*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'opera*',
                'label': 'http.http_user_agent: opera*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'edge*',
                'label': 'http.http_user_agent: edge*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'mozilla*',
                'label': 'http.http_user_agent: mozilla*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'wget*',
                'label': 'http.http_user_agent: wget*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'curl*',
                'label': 'http.http_user_agent: curl*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'perl*',
                'label': 'http.http_user_agent: perl*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'python*',
                'label': 'http.http_user_agent: python*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'http',
                'label': 'app_proto: http',
                'fullString': True,
                'query': 'filter',
                'negated': False,
                'id': 'app_proto'
            }
        ],
        'name': 'Hunt: Suspicious HTTP User Agents - 1',
        'page': 'DASHBOARDS',
        'description': 'The filter set returns events that have HTTP user agents that are not usually seen too much. Hence making it a good candidate for further investigations.',
        'share': 'static'
    },
    {
        'content': [
            {
                'value': '*(*',
                'label': 'http.http_user_agent: *(*',
                'fullString': False,
                'query': 'filter',
                'negated': True,
                'id': 'http.http_user_agent'
            },
            {
                'value': 'http',
                'label': 'app_proto: http',
                'fullString': True,
                'query': 'filter',
                'negated': False,
                'id': 'app_proto'
            }
        ],
        'name': 'Hunt: Suspicious HTTP User Agents -2',
        'page': 'DASHBOARDS',
        'description': 'The filter set returns events that have HTTP user agents that are not usually seen too much. Hence making it a good candidate for further investigations. This is second hunt variant of the filter.',
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
    },
    {
        "content": [
            {
                "id": "alert.signature",
                "value": "*outdated*",
                "label": "alert.signature: *outdated*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Policy: Outdated software",
        "page": "DASHBOARDS",
        "description": "Outdated or old software that needs upgrades or security patching. It presents a risk and policy violation.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "alert.signature",
                "value": "*vulnerable*",
                "label": "alert.signature: *vulnerable*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Policy: Vulnerable software",
        "page": "DASHBOARDS",
        "description": "Vulnerable software that needs upgrades or security patching. It presents a risk and policy violation.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "alert.signature",
                "value": "*CVE-*",
                "label": "alert.signature: *CVE-*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Policy: CVE global detection",
        "page": "DASHBOARDS",
        "description": "The guided filter set returns any CVE related events. It is a good starting point for policy violations review, CVE detection or threat hunting.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "alert.signature",
                "value": "*phishing*",
                "label": "alert.signature: *phishing*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Phishing: Phishing general detection",
        "page": "DASHBOARDS",
        "description": "This guided filter set returns events related to possible attempts of phishing and policy violations.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "Message: adware_pup",
                "id": "msg",
                "value": "adware_pup",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.category",
                "value": "Possibly Unwanted Program Detected",
                "label": "alert.category: Possibly Unwanted Program Detected",
                "fullString": True,
                "negated": False
            },
        ],
        "name": "Adware: PUP",
        "page": "DASHBOARDS",
        "description": "Potentially unwanted program detected. Usually indicative of policy violation on corporate network.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "msg: web_client",
                "id": "msg",
                "value": "web_client",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.signature",
                "value": "*encoded*",
                "label": "alert.signature: *encoded*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Hunt: web client encoded values",
        "page": "DASHBOARDS",
        "description": "This filter set returns encoded values found in the HTTP URLs or  payloads of the alert events. Needs investigation as to where from and why these events appear.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "msg: web_server",
                "id": "msg",
                "value": "web_server",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.signature",
                "value": "*encoded*",
                "label": "alert.signature: *encoded*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Hunt: web server encoded values",
        "page": "DASHBOARDS",
        "description": "This filter set returns encoded values found in the HTTP URLs or  payloads of the alert events. Needs investigation as to where from and why these events appear.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "msg: shellcode",
                "id": "msg",
                "value": "shellcode",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.signature",
                "value": "*encoded*",
                "label": "alert.signature: *encoded*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Hunt: possible encoded shell code strings",
        "page": "DASHBOARDS",
        "description": "This filter set returns possible encoded shell code strings values found in the payloads of the alert events. Needs investigation as to where from and why these events appear.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "es_filter: -http.http_user_agent.keyword:/.{55}.*/",
                "id": "es_filter",
                "value": "-http.http_user_agent.keyword:/.{55}.*/",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "http.http_user_agent",
                "value": "*",
                "label": "http.http_user_agent: *",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Hunt: Unusual in length http user agents",
        "page": "DASHBOARDS",
        "description": "This filter set returns unusual in length HTTP user agents. A good starting point for revealing custom, scripting languages or add on software user agents.",
        "share": "static"
    },
    {
        "content": [
            {
                "value": "*java*",
                "label": "http.http_user_agent: *java*",
                "fullString": False,
                "query": "filter",
                "negated": False,
                "id": "http.http_user_agent"
            },
        ],
        "name": "Info: Java HTTP User Agents",
        "page": "DASHBOARDS",
        "description": "This filter set returns results of HTTP based signatures that have Java http user agent.  Mostly informational unless it comes from unexpected locations in the network.",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "http.http_user_agent",
                "value": "*shockwave*",
                "label": "http.http_user_agent: *shockwave*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Info: Shockwave Flash HTTP User Agents",
        "page": "DASHBOARDS",
        "description": "This filter set returns results for Shockwave Flash HTTP user agents observed in alert events..",
        "share": "static"
    },
    {
        "content": [
            {
                "id": "alert.signature",
                "value": "*cleartext*",
                "label": "alert.signature: *cleartext*",
                "fullString": False,
                "negated": False
            },
            {
                "id": "alert.category",
                "value": "Potential Corporate Privacy Violation",
                "label": "alert.category: Potential Corporate Privacy Violation",
                "fullString": True,
                "negated": False
            },
        ],
        "name": "Policy: Clear text password - 1",
        "page": "DASHBOARDS",
        "description": "Policy violation. Clear text password.",
        "share": "static"
    },
    {
        "content": [
            {
                "label": "Message: password",
                "id": "msg",
                "value": "password",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "label": "msg: unencrypted",
                "id": "msg",
                "value": "unencrypted",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.category",
                "value": "Potential Corporate Privacy Violation",
                "label": "alert.category: Potential Corporate Privacy Violation",
                "fullString": True,
                "negated": False
            },
        ],
        "name": "Policy: Clear text password - 2",
        "page": "DASHBOARDS",
        "description": "Policy violation. Unencrypted password.",
        "share": "static"
    }
]
