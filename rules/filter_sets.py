

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
        'description': 'This filter highlights the events which have rarely triggered. These low noise alerts can sometimes hide valuable artifacts and discoveries.',
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
        'description': 'This filter highlights the trojan-related events.',
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
        'description': 'This filter highlights the malware-related events.',
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
        'description': 'This filter highlights all the events that are generated from  rules with the "hunting" designation.',
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
        'description': 'This filter highlights all the events related to executable files, including downloads, posts, and others. This usually provides interesting data that warrants further investigation.',
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
        'description': 'This filter highlights all the events that take place via HTTP and are either posting or downloading executables.',
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
        "description": "This filter highlights all the events that include HTTP requests and responses directly to an internal IP address - not a domain name. This activity may be suspicious because a domain name is typically part of the transaction when communicating with servers inside the network. While common in some development environments, it could also indicate lateral movement.",
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
        "name": "Hunt: HTTP non-internal  direct IP requests and replies",
        "page": "DASHBOARDS",
        "description": "This filter highlights all the events that indicate HTTP requests and responses directly by IP - not using a domain name. This activity may be suspicious because a domain name is typically part of the transaction when communicating with servers outside the network (non private/internal IPs).",
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
        "description": 'This filter highlights the events that include "Admin" or "Administrator" in their alert payload.',
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
        "description": 'This filter highlights the events containing "root" in the payloads.',
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
        "description": 'Hunt: This filter highlights all the events that indicate HTTP payloads containing "admin".',
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
        "description": 'This filter highlights the events identifying "root" or "admin" in the TLS payload.',
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
                "id": "tls.version",
                "value": "TLS 1.2",
                "label": "tls.version: TLS 1.2",
                "fullString": True,
                "negated": True
            },
            {
                "id": "tls.version",
                "value": "TLS 1.3",
                "label": "tls.version: TLS 1.3",
                "fullString": True,
                "negated": True
            },
            {
                "id": "tls.version",
                "value": "UNDETERMINED",
                "label": "tls.version: UNDETERMINED",
                "fullString": True,
                "negated": True
            }
        ],
        "name": "Policy: Old TLS versions",
        "page": "DASHBOARDS",
        "description": "This filter highlights events that identify the use of TLS encryption version prior to version 1.2.",
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "ftp*",
                "label": "app_proto: ftp*",
                "fullString": False,
                "negated": False
            }
        ],
        "name": "Policy: FTP clear text alerts and sightings",
        "page": "DASHBOARDS",
        "description": "This filter set returns FTP and FTP based data alert events.",
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
        'description': 'This filter highlights all the events that include HTTP POST requests. This type of request can hide malicious activity.',
    },
    {
        "content": [
            {
                "id": "app_proto",
                "value": "smtp",
                "label": "app_proto: smtp",
                "fullString": False,
                "negated": False
            }
        ],
        "name": "Policy: SMTP clear text events",
        "page": "DASHBOARDS",
        "description": "This filter set returns SMTP based alert events.",
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
        'description': 'This filter highlights events that are using HTTP application layer protocol but with an user agent that includes specific characters not common to user agents.',
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
        'description': 'This filter highlights events that are using HTTP application layer protocol but with an user agent that is not common - aka not mozilla/firefox/opera/edge/wget and similar.',
    },
    {
        'content': [
            {
                'value': 'CURRENT_EVENTS',
                'label': 'Message: CURRENT_EVENTS',
                'fullString': False,
                'query': 'filter',
                'negated': False,
                'id': 'msg'
            }
        ],
        'name': 'Hunt: Current events',
        'page': 'DASHBOARDS',
        'description': 'This filter highlights the events that trigger based on the CURRENT_EVENTS ET rules',
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
        'description': 'This filter highlights all the events with DNS-related metadata.',
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
        'description': 'This filter highlights the events classified as "Severity 1" by one of the rulesets.',
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
        'description': 'This filter highlights the SSH-related events that have no libssh or openssh client version. ',
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
        'description': 'This informational filter highlights the HTTP-based events that contain Python HTTP User Agents.',
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
        'description': 'This informational filter highlights the HTTP-based events that contain Curl HTTP User Agents.',
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
        'description': 'This informational filter highlights the HTTP-based events that contain Perl HTTP User Agents.',
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
        'description': 'This informational filter highlights the HTTP-based events that contain Wget HTTP User Agents.',
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
        "description": "This filter highlights outdated or old software that should be upgraded or patched.",
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
        "description": "This filter highlights known-vulnerable software that should be upgraded or patched.",
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
        "description": "This filter highlights events associated with publicly-identified vulnerabilities (CVE issued).",
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
        "description": 'This filter highlights events that contain the keyword "phishing", identifying all activity that may be considered possible phishing attempts.',
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
    },
    {
        "content": [
            {
                "label": "Message: web_client",
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
        "description": "This filter highlights the events that have encoded values in the client side HTTP URLs or payload.",
    },
    {
        "content": [
            {
                "label": "Message: web_server",
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
        "description": "This filter highlights the events that have encoded values in the server side HTTP URLs or payload.",
    },
    {
        "content": [
            {
                "label": "Message: shellcode",
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
        "description": "This filter highlights the events that have encoded shellcode string values in the payload.",
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
        "description": "This filter highlights the events containing HTTP user agents which contain fewer than 55 characters.",
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
        "description": "This informational filter highlights the HTTP-based events that contain Curl Java User Agents.",
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
        "description": "This informational filter highlights the HTTP-based events that contain Shockwave Flash HTTP User Agents.",
    },
    {
        "content": [
            {
                "label": "Message: url",
                "id": "msg",
                "value": "url",
                "negated": False,
                "query": "filter",
                "fullString": False
            },
            {
                "id": "alert.signature",
                "value": "short*",
                "label": "alert.signature: short*",
                "fullString": False,
                "negated": False
            },
        ],
        "name": "Hunt: URL Shortener services",
        "page": "DASHBOARDS",
        "description": "This filter set returns requests made to known URL shortener services.",
    },
    {
        "content": [
            {
                "id": "alert.metadata.stamus_classification",
                "value": "lateral",
                "label": "alert.metadata.stamus_classification: lateral",
                "fullString": True,
                "negated": False
            },
            {
                "id": "alert.metadata.source",
                "value": "smb_lateral",
                "label": "alert.metadata.source: smb_lateral",
                "fullString": True,
                "negated": False
            },
            {
                "id": "alert.metadata.signature_severity",
                "value": "Critical",
                "label": "alert.metadata.signature_severity: Critical",
                "fullString": True,
                "negated": False
            }
        ],
        "name": "Hunt: Stamus critical lateral SMB, DCERPC",
        "page": "DASHBOARDS",
        "description": "This filter set returns SMB/DCERPC  events that are actively changing, configuring, adding or deleting settings and services remotely.",
    },
    {
        "content": [
            {
                "id": "alert.metadata.stamus_classification",
                "value": "lateral",
                "label": "alert.metadata.stamus_classification: lateral",
                "fullString": True,
                "negated": False
            },
            {
                "id": "alert.metadata.source",
                "value": "smb_lateral",
                "label": "alert.metadata.source: smb_lateral",
                "fullString": True,
                "negated": False
            },
            {
                "id": "alert.metadata.signature_severity",
                "value": "Informational",
                "label": "alert.metadata.signature_severity: Informational",
                "fullString": True,
                "negated": False
            }
        ],
        "name": "Hunt: Stamus lateral SMB, DCERPC",
        "page": "DASHBOARDS",
        "description": "This filter set returns lateral related events like scans or SMB/DCERPC MS protocol related queries.",
    },
    {
        "content": [
            {
                "id": "alert.metadata.lateral_function",
                "value": "OpenLocalMachine",
                "label": "alert.metadata.lateral_function: OpenLocalMachine",
                "fullString": True,
                "negated": False
            },
        ],
        "name": "Hunt: Remote Administration Console OpenLocalMachine",
        "page": "DASHBOARDS",
        "description": "This filter set returns events that are indicative of remotely opening the administration console of a Windows OS.",
    },
    {
        "content": [
            {
                "id": "alert.metadata.lateral_function",
                "value": "OpenClassesRoot",
                "label": "alert.metadata.lateral_function: OpenClassesRoot",
                "fullString": True,
                "negated": False
            },
        ],
        "name": "Hunt: Remote Administration Registry HKEY_CLASSES_ROOT",
        "page": "DASHBOARDS",
        "description": "This filter set returns events that are indicative of remotely opening the registry HKEY_CLASSES_ROOT  of a Windows OS.",
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
        "description": "This filter highlights events associated with clear text passwords.",
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
                "label": "Message: unencrypted",
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
        "description": "This filter highlights events associated with unencrypted passwords.",
    }
]
