IOC_MAPPING = {
    'hostname': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP hostname IOC {name}"; flow:established; http.host; dataset:isset, {name}, type string, load {name}; metadata:ioc_key http.host, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
            'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS SNI IOC {name}"; flow:established; tls.sni; dataset:isset, {name}, type string, load {name}; metadata:ioc_key tls.sni, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)'
        ],
    },
    'domain_name': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Hostname domain name IOC {name}"; flow:established; http.host; domain; dataset:isset, {name}, type string, load {name}; metadata: ioc_key http.host, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at:{updated_at}{metadata}; sid:{sid}; rev:{rev};)',
            'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS SNI domain name IOC {name}"; flow:established; tls.sni; domain; dataset:isset, {name}, type string, load {name}; metadata:ioc_key tls.sni, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)'
        ]
    },
    'ip': {
        'type': 'string',
        'encoding': None,
        'validator': None,
        'signatures': [
            'alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"IP IOC {name}"; flow:established; threshold: type limit, track by_both, count 1, seconds 720; ip.dst; dataset:isset, {name}, type ip, load {name}; metadata:ioc_key ip.dst, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'filename': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert tcp $HOME_NET any -> any any (msg:"Filename IOC {name}"; flow:established; file.name; dataset:isset, {name}, type string, load {name}; metadata:ioc_key file.name, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'url': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"URL IOC {name}"; flow:established; http.uri; dataset:isset, {name}, type string, load {name}; metadata:ioc_key http.uri, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'http-user-agent': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP User Agent IOC {name}"; flow:established; http.user_agent; dataset:isset, {name}, type string, load {name}; metadata:ioc_key http.user_agent, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'http-cookie': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Cookie IOC {name}"; flow:established; http.cookie; dataset:isset, {name}, type string, load {name}; metadata:ioc_key http.cookie, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    }
}
