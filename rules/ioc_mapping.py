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
    }
}
