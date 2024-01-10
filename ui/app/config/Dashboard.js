export const dashboard = [
  {
    panelId: 'basic',
    title: 'Basic Information',
    position: 1,
    items: [
      {
        i: 'alert.signature',
        title: 'Signatures',
      },
      {
        i: 'alert.category',
        title: 'Categories',
      },
      {
        i: 'alert.severity',
        title: 'Severities',
        format: value => {
          switch (value.toString()) {
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
        i: 'host',
        title: 'Probes',
      },
    ],
  },
  {
    panelId: 'metadata',
    title: 'Metadata',
    position: 2,
    items: [
      {
        i: 'alert.metadata.signature_severity',
        title: 'Signature Severities',
      },
      {
        i: 'alert.metadata.attack_target',
        title: 'Attack Targets',
      },
      {
        i: 'alert.metadata.affected_product',
        title: 'Affected Products',
      },
      {
        i: 'alert.metadata.malware_family',
        title: 'Malware Families',
      },
    ],
  },
  {
    panelId: 'mitre',
    title: 'MITRE ATT&CK Information',
    position: 3,
    items: [
      {
        i: 'alert.metadata.mitre_tactic_id',
        title: 'Tactic IDs',
      },
      {
        i: 'alert.metadata.mitre_tactic_name',
        title: 'Tactic Names',
      },
      {
        i: 'alert.metadata.mitre_technique_id',
        title: 'Technique IDs',
      },
      {
        i: 'alert.metadata.mitre_technique_name',
        title: 'Technique Names',
      },
    ],
  },
  {
    panelId: 'organizational',
    title: 'Organizational Information',
    position: 7,
    items: [
      {
        i: 'alert.source.ip',
        title: 'Sources',
      },
      {
        i: 'alert.target.ip',
        title: 'Targets',
      },
      {
        i: 'geoip.country_name',
        title: 'Country Names',
      },
      {
        i: 'geoip.city_name',
        title: 'City Names',
      },
    ],
  },
  {
    panelId: 'ip',
    title: 'IP Information',
    position: 8,
    items: [
      {
        i: 'src_ip',
        title: 'Source IPs',
      },
      {
        i: 'dest_ip',
        title: 'Destinations IP',
      },
      {
        i: 'src_port',
        title: 'Source Ports',
      },
      {
        i: 'dest_port',
        title: 'Destinations Ports',
      },
      {
        i: 'proto',
        title: 'IP Protocols',
      },
      {
        i: 'vlan',
        title: 'Vlans',
      },
      {
        i: 'tunnel.src_ip',
        title: 'Tunnel Source IPs',
      },
      {
        i: 'tunnel.dest_ip',
        title: 'Tunnel Destination IPs',
      },
      {
        i: 'tunnel.proto',
        title: 'Tunnel Protocols',
      },
      {
        i: 'tunnel.depth',
        title: 'Tunnel Depths',
      },
    ],
  },
  {
    panelId: 'http',
    id: 'http',
    title: 'HTTP Information',
    position: 9,
    items: [
      {
        i: 'http.hostname',
        title: 'Hostnames',
      },
      {
        i: 'http.url',
        title: 'URLs',
      },
      {
        i: 'http.status',
        title: 'Statuses',
      },
      {
        i: 'http.http_user_agent',
        title: 'Useragents',
      },
      {
        i: 'http.http_refer',
        title: 'Referrers',
      },
    ],
  },
  {
    panelId: 'dns',
    title: 'DNS Information',
    position: 10,
    items: [
      {
        i: 'dns.query.rrname',
        title: 'Names',
      },
      {
        i: 'dns.query.rrtype',
        title: 'Types',
      },
    ],
  },
  {
    panelId: 'tls',
    title: 'TLS Information',
    position: 11,
    items: [
      {
        i: 'tls.sni',
        title: 'Server Names Indication',
      },
      {
        i: 'tls.subject',
        title: 'Subject DNs',
      },
      {
        i: 'tls.issuerdn',
        title: 'Issuer DNs',
      },
      {
        i: 'tls.fingerprint',
        title: 'Fingerprints',
      },
      {
        i: 'tls.ja4.hash',
        title: 'JA4 Hashes',
      },
      {
        i: 'tls.ja3.hash',
        title: 'JA3 Hashes',
      },
      {
        i: 'tls.ja3.agent',
        title: 'JA3 User-Agents',
      },
      {
        i: 'tls.ja3s.hash',
        title: 'JA3S Hashes',
      },
    ],
  },
  {
    panelId: 'smtp',
    title: 'SMTP Information',
    position: 12,
    items: [
      {
        i: 'smtp.mail_from',
        title: 'Mail From',
      },
      {
        i: 'smtp.rcpt_to',
        title: 'RCPT To',
      },
      {
        i: 'smtp.helo',
        title: 'Helo',
      },
    ],
  },
  {
    panelId: 'smb',
    title: 'SMB Information',
    position: 13,
    items: [
      {
        i: 'smb.command',
        title: 'Commands',
      },
      {
        i: 'smb.status',
        title: 'Statuses',
      },
      {
        i: 'smb.filename',
        title: 'Filenames',
      },
      {
        i: 'smb.share',
        title: 'Shares',
      },
    ],
  },
  {
    panelId: 'ssh',
    title: 'SSH Information',
    position: 14,
    items: [
      {
        i: 'ssh.client.software_version',
        title: 'Client Software',
      },
      {
        i: 'ssh.client.proto_version',
        title: 'Client Version',
      },
      {
        i: 'ssh.server.software_version',
        title: 'Server Software',
      },
      {
        i: 'ssh.server.proto_version',
        title: 'Server Version',
      },
    ],
  },
];
