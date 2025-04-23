from rules.validators import validate_hostname, validate_dns, validate_address_or_network


IOC_MAPPING = {
    'hostname': {
        'type': 'string',
        'encoding': 'b64',
        'validator': validate_hostname,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP IOC {name}"; http.host; dataset:isset, {name}, type string, load {name}; metadata:ioc_key http.hostname, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
            'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP IOC {name}"; tls.sni; dataset:isset, {name}, type string, load {name}; metadata:ioc_key tls.sni, ioc_asset src_ip, stamus_classification stamus_ioc_custom, provider Stamus, created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)'
        ],
    },
    'domain_name': {
        'type': 'string',
        'encoding': 'b64',
        'validator': validate_dns,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP IOC {name}"; http.host; domain; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at:{updated_at}{metadata}; sid:{sid}; rev:1;)',
            'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP IOC {name}"; tls.sni; domain; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)'
        ]
    },
    'ip': {
        'type': 'string',
        'encoding': None,
        'validator': validate_address_or_network,
        'signatures': [
            'alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"IP IOC {name}"; ip.dst; dataset:isset, {name}, type ip, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'filename': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"File IOC {name}"; file.name; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'url': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"URL IOC {name}"; http.uri; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'http-user-agent': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP User Agent IOC {name}"; http.user_agent; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    },
    'http-cookie': {
        'type': 'string',
        'encoding': 'b64',
        'validator': None,
        'signatures': [
            'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Cookie IOC {name}"; http.cookie; dataset:isset, {name}, type string, load {name}; metadata:created_at {created_at}, updated_at {updated_at}{metadata}; sid:{sid}; rev:{rev};)',
        ]
    }
}
