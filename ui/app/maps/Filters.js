import { KillChainStepsEnum } from 'ui/maps/KillChainStepsEnum';
import FilterValidationType from 'ui/maps/FilterValidationType';
import FilterValueType from 'ui/maps/FilterValueType';

export const FilterCategory = {
  EVENT: 'EVENT',
  HISTORY: 'HISTORY',
  SIGNATURE: 'SIGNATURE',
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
  /* Signature filters */
  {
    title: 'Alerts min',
    id: 'hits_min',
    category: FilterCategory.SIGNATURE,
    wildcardable: false,
    negatable: false,
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
  },
  {
    title: 'Alerts max',
    id: 'hits_max',
    category: FilterCategory.SIGNATURE,
    wildcardable: false,
    negatable: false,
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
  },
  {
    title: 'Message',
    id: 'msg',
    category: [FilterCategory.SIGNATURE, FilterCategory.EVENT],
    wildcardable: false,
    negatable: true,
    onNegate: () => ({
      id: 'not_in_msg',
    }),
    defaults: {
      wildcard: true,
    },
  },
  {
    title: 'Message',
    id: 'not_in_msg',
    category: [FilterCategory.SIGNATURE, FilterCategory.EVENT],
    wildcardable: false,
    negatable: true,
    onNegate: () => ({
      id: 'msg',
    }),
  },
  {
    title: 'Content',
    id: 'content',
    category: [FilterCategory.SIGNATURE, FilterCategory.EVENT],
    wildcardable: false,
    onNegate: () => ({
      id: 'not_in_content',
    }),
    defaults: {
      wildcard: true,
    },
  },
  {
    title: 'Content',
    id: 'not_in_content',
    category: [FilterCategory.SIGNATURE, FilterCategory.EVENT],
    wildcardable: false,
    onNegate: () => ({
      id: 'content',
    }),
  },
  /* Event filters */
  {
    title: 'Command',
    id: 'smb.command',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Severity',
    id: 'alert.severity',
    category: FilterCategory.EVENT,
    wildcardable: false,
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
    wildcardable: false,
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
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
    wildcardable: false,
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
    wildcardable: false,
    type: FilterType.IP,
    convertible: 'host_id.ip',
  },
  {
    title: 'Source port',
    id: 'src_port',
    category: FilterCategory.EVENT,
    type: FilterType.PORT,
    valueType: FilterValueType.NUMBER,
    convertible: 'host_id.services.port',
    wildcardable: false,
  },
  {
    title: 'Port',
    id: 'port',
    category: FilterCategory.EVENT,
    type: FilterType.PORT,
    wildcardable: false,
    convertible: 'host_id.services.port',
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
  },
  {
    title: 'Destination Network',
    id: 'net_info.dest_agg',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Destination IP',
    id: 'dest_ip',
    wildcardable: false,
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
    wildcardable: false,
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
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Tunnel Source IP',
    id: 'tunnel.src_ip',
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Tunnel Destination IP',
    id: 'tunnel.dest_ip',
    wildcardable: false,
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
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Source port',
    id: 'alert.source.port',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  {
    title: 'Target IP',
    id: 'alert.target.ip',
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'Target port',
    id: 'alert.target.port',
    category: FilterCategory.EVENT,
    wildcardable: false,
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
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Bytes to client',
    id: 'flow.bytes_toclient',
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Pkts to server',
    id: 'flow.pkts_toserver',
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Pkts to client',
    id: 'flow.pkts_toclient',
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Flow ID',
    id: 'flow_id',
    wildcardable: false,
    category: FilterCategory.EVENT,
  },
  {
    title: 'Country',
    id: 'geoip.country_name',
    category: FilterCategory.EVENT,
  },
  {
    title: 'City',
    id: 'geoip.city_name',
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
    wildcardable: false,
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
    wildcardable: false,
    category: FilterCategory.EVENT,
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
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
    wildcardable: false,
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
    wildcardable: false,
    valueType: FilterValueType.NUMBER,
    validationType: FilterValidationType.POSITIVE_INT,
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
    title: 'Issuer DN',
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
    title: 'Serial',
    id: 'tls.serial',
    category: FilterCategory.EVENT,
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
    wildcardable: false,
    type: FilterType.IP,
    validationType: FilterValidationType.IP,
    convertible: 'host_id.ip',
  },
  {
    title: 'DNS rdata',
    id: 'dns.rdata',
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS answers rdata',
    id: 'dns.answers.rdata',
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS grouped A',
    id: 'dns.grouped.A',
    wildcardable: false,
    category: FilterCategory.EVENT,
    type: FilterType.IP,
  },
  {
    title: 'DNS grouped AAAA',
    id: 'dns.grouped.AAAA',
    wildcardable: false,
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
    title: 'Signature Severity',
    id: 'alert.metadata.signature_severity',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Attack Target',
    id: 'alert.metadata.attack_target',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Affected Product',
    id: 'alert.metadata.affected_product',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Malware Family',
    id: 'alert.metadata.malware_family',
    category: FilterCategory.EVENT,
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
    title: 'HTTP Refer Subdomain',
    id: 'http.http_refer_info.subdomain',
    category: FilterCategory.EVENT,
    type: FilterType.HOSTNAME,
  },
  {
    title: 'Referrer TLD',
    id: 'http.http_refer_info.tld',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Referrer Resource Path',
    id: 'http.http_refer_info.resource_path',
    category: FilterCategory.EVENT,
  },
  {
    title: 'Referrer Schema',
    id: 'http.http_refer_info.scheme',
    category: FilterCategory.EVENT,
  },
  {
    title: 'HTTP Refer Domain Without TLD',
    id: 'http.http_refer_info.domain_without_tld',
    category: FilterCategory.EVENT,
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
    title: 'ES Filter',
    id: 'es_filter',
    category: FilterCategory.EVENT,
    wildcardable: false,
  },
  /* HISTORY */
  {
    title: 'User',
    id: 'username',
    category: FilterCategory.HISTORY,
  },
  {
    title: 'Comment',
    id: 'comment',
    category: FilterCategory.HISTORY,
  },
  {
    title: 'Client IP',
    id: 'client_ip',
    category: FilterCategory.HISTORY,
    validationType: FilterValidationType.IP,
  },
  {
    title: 'Action Type',
    id: 'action_type',
    category: FilterCategory.HISTORY,
  },
];
