import { KillChainStepsEnum } from 'ui/maps/KillChainStepsEnum';

export const FilterCategory = {
  EVENT: 'EVENT',
  HISTORY: 'HISTORY',
};

export const FilterType = {
  IP: 'IP',
  PORT: 'PORT',
  MITRE: 'MITRE',
  USERNAME: 'USERNAME',
  HOSTNAME: 'HOSTNAME',
  ROLE: 'ROLE',
  NETWORK_INFO: 'NETWORK_INFO',
  GENERIC: 'GENERIC',
};

export const FiltersList = [
  {
    title: 'Command',
    id: 'smb.command',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Severity',
    id: 'alert.severity',
    category: FilterCategory.EVENT,
    format: value => {
      switch (value?.toString()) {
        case '1':
          return 'Severe';
        case '2':
          return 'Suspicious';
        case '3':
          return 'Contextual';
        default:
          return value;
      }
    },
  },
  {
    title: 'Status',
    id: 'smb.status',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Filename',
    id: 'smb.filename',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Share',
    id: 'smb.share',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Session ID',
    id: 'smb.session_id',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Source Network',
    id: 'alert.source.net_info_agg',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Target Network',
    id: 'alert.target.net_info_agg',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Signature',
    id: 'alert.signature',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Signature ID',
    id: 'alert.signature_id',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Category',
    id: 'alert.category',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Revision',
    id: 'alert.rev',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Tagged',
    id: 'alert.tag',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Source Network',
    id: 'net_info.src_agg',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Source IP',
    id: 'src_ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
    convertible: 'host_id.ip',
  },
  {
    title: 'Source port',
    id: 'src_port',
    category: FilterCategory.EVENT,
    type: FilterType.PORT,
    convertible: 'host_id.services.port',
  },
  {
    title: 'Port',
    id: 'port',
    category: FilterCategory.EVENT,
    type: FilterType.PORT,
    convertible: 'host_id.services.port',
  },
  {
    title: 'Destination Network',
    id: 'net_info.dest_agg',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Destination IP',
    id: 'dest_ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
    convertible: 'host_id.ip',
  },
  {
    title: 'Destination port',
    id: 'dest_port',
    category: FilterCategory.EVENT,
    type: FilterType.PORT,
    convertible: 'host_id.services.port',
  },
  {
    title: 'IP protocol',
    id: 'proto',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.proto',
  },
  {
    title: 'Application protocol',
    id: 'app_proto',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.values.app_proto',
  },
  {
    title: 'Original application protocol',
    id: 'app_proto_orig',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Probe',
    id: 'host',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Network interface',
    id: 'in_iface',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Vlan',
    id: 'vlan',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Tunnel Source IP',
    id: 'tunnel.src_ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Tunnel Destination IP',
    id: 'tunnel.dest_ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Tunnel Protocol',
    id: 'tunnel.proto',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Tunnel Depth',
    id: 'tunnel.depth',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Source IP',
    id: 'alert.source.ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Source port',
    id: 'alert.source.port',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Target IP',
    id: 'alert.target.ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Target port',
    id: 'alert.target.port',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Lateral movement',
    id: 'alert.lateral',
    category: FilterCategory.EVENT,
  },
  {
    title: 'FQDN Source',
    id: 'fqdn.src',
    category: FilterCategory.EVENT,
  },
  {
    title: 'FQDN Destination',
    id: 'fqdn.dest',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Queried Name',
    id: 'dns.query.rrname',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Queried Type',
    id: 'dns.query.rrtype',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Flow start',
    id: 'flow.start',
    category: FilterCategory.EVENT,
    filterable: false,
  },
  {
    title: 'Client IP',
    id: 'flow.src_ip',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Server IP',
    id: 'flow.dest_ip',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Bytes to server',
    id: 'flow.bytes_toserver',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Bytes to client',
    id: 'flow.bytes_toclient',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Pkts to server',
    id: 'flow.pkts_toserver',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Pkts to client',
    id: 'flow.pkts_toclient',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Flow ID',
    id: 'flow_id',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Country',
    id: 'geoip.country_name',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Country Code',
    id: 'geoip.country.iso_code',
    category: FilterCategory.EVENT,
  },
  {
    title: 'AS Number',
    id: 'geoip.provider.autonomous_system_number',
    category: FilterCategory.EVENT,
  },
  {
    title: 'AS Organization',
    id: 'geoip.provider.autonomous_system_organization',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Host',
    id: 'http.hostname',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'URL',
    id: 'http.url',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Status',
    id: 'http.status',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Method',
    id: 'http.http_method',
    category: FilterCategory.EVENT,
  },
  {
    title: 'User Agent',
    id: 'http.http_user_agent',
    category: FilterCategory.EVENT,
    convertible: 'host_id.http.user_agent.agent',
  },
  {
    title: 'Referrer',
    id: 'http.http_refer',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Port',
    id: 'http.http_port',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Content Type',
    id: 'http.http_content_type',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Length',
    id: 'http.length',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Server',
    id: 'http.server',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Accept Language',
    id: 'http.accept_language',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Protocol',
    id: 'http.protocol',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Subject',
    id: 'tls.subject',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.values.tls.subject',
  },
  {
    title: 'Issuer',
    id: 'tls.issuerdn',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.values.tls.issuerdn',
  },
  {
    title: 'Server Name Indication',
    id: 'tls.sni',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Not Before',
    id: 'tls.notbefore',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Not After',
    id: 'tls.notafter',
    category: FilterCategory.EVENT,
  },
  {
    title: 'JA3',
    id: 'tls.ja3.hash',
    category: FilterCategory.EVENT,
    convertible: 'host_id.tls.ja3.hash',
  },
  {
    title: 'User-Agent',
    id: 'tls.ja3.agent',
    category: FilterCategory.EVENT,
    convertible: 'host_id.tls.ja3.agent',
  },
  {
    title: 'Fingerprint',
    id: 'tls.fingerprint',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.values.tls.fingerprint',
  },
  {
    title: 'JA3S',
    id: 'tls.ja3s.hash',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Version',
    id: 'tls.version',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Cipher Suite',
    id: 'tls.cipher_suite',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Cipher Security',
    id: 'tls.cipher_security',
    category: FilterCategory.EVENT,
  },
  {
    title: 'From',
    id: 'smtp.mail_from',
    category: FilterCategory.EVENT,
    type: FilterType.USERNAME,
  },
  {
    title: 'To',
    id: 'smtp.rcpt_to',
    category: FilterCategory.EVENT,
    type: FilterType.USERNAME,
  },
  {
    title: 'Helo',
    id: 'smtp.helo',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Client Software',
    id: 'ssh.client.software_version',
    category: FilterCategory.EVENT,
    convertible: 'host_id.ssh.client.software_version',
  },
  {
    title: 'Client Version',
    id: 'ssh.client.proto_version',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Server Software',
    id: 'ssh.server.software_version',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Server Version',
    id: 'ssh.server.proto_version',
    category: FilterCategory.EVENT,
    convertible: 'host_id.services.values.ssh.server.software_version',
  },
  {
    title: 'Source MAC',
    id: 'ether.src_mac',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Destination MAC',
    id: 'ether.dest_mac',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Asset',
    id: 'stamus.asset',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Offender',
    id: 'stamus.source',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Threat',
    id: 'stamus.threat_name',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Family',
    id: 'stamus.family_name',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Kill Chain Phase',
    id: 'stamus.kill_chain',
    category: FilterCategory.EVENT,
    format: value => KillChainStepsEnum[value] || value,
  },
  {
    title: 'Method ID',
    id: 'stamus.threat_id',
    category: FilterCategory.EVENT,
  },
  {
    title: 'IP',
    id: 'ip',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
    convertible: 'host_id.ip',
  },
  {
    title: 'DNS rdata',
    id: 'dns.rdata',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS answers rdata',
    id: 'dns.answers.rdata',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS grouped A',
    id: 'dns.grouped.A',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS grouped AAAA',
    id: 'dns.grouped.AAAA',
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Mitre Tactic ID',
    id: 'alert.metadata.mitre_tactic_id',
    category: FilterCategory.EVENT,
    type: FilterType.MITRE,
    format: value => value?.replaceAll('_', '') || null,
  },
  {
    title: 'Mitre Technique ID',
    id: 'alert.metadata.mitre_technique_id',
    category: FilterCategory.EVENT,
    type: FilterType.MITRE,
    format: value => value?.replaceAll('_', '') || null,
  },
  {
    title: 'Mitre Tactic Name',
    id: 'alert.metadata.mitre_tactic_name',
    category: FilterCategory.EVENT,
    type: FilterType.MITRE,
    format: value => value?.replaceAll('_', '') || null,
  },
  {
    title: 'Mitre Technique Name',
    id: 'alert.metadata.mitre_technique_name',
    category: FilterCategory.EVENT,
    type: FilterType.MITRE,
    format: value => value?.replaceAll('_', '') || null,
  },
  {
    title: 'Host Domain',
    id: 'hostname_info.domain',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'Host Subdomain',
    id: 'hostname_info.subdomain',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'Host TLD',
    id: 'hostname_info.tld',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Host Domain Without TLD',
    id: 'hostname_info.domain_without_tld',
    category: FilterCategory.EVENT,
  },
  {
    title: 'HTTP Refer Domain',
    id: 'http.http_refer_info.domain',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'TLS SNI',
    id: 'tls.sni',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'HTTP Refer Host',
    id: 'http.http_refer_info.host',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'SMTP Helo',
    id: 'smtp.helo',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'Hostname Host',
    id: 'hostname_info.host',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'Command',
    id: 'smb.command',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Status',
    id: 'smb.status',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Filename',
    id: 'smb.filename',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Share',
    id: 'smb.share',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Alerts min',
    id: 'hits_min',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Alerts max',
    id: 'hits_max',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Message',
    id: 'msg',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Not in Message',
    id: 'not_in_msg',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'ES Filter',
    id: 'es_filter',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Not in Content',
    id: 'not_in_content',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Content',
    id: 'content',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
];
