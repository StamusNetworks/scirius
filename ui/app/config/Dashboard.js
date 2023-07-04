export const dashboard = {
  basic: {
    title: 'Basic Information',
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
  metadata: {
    title: 'Metadata',
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
  mitre: {
    title: 'MITRE ATT&CK Information',
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
  organizational: {
    id: 'organizational',
    title: 'Organizational Information',
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
  ip: {
    id: 'ip',
    title: 'IP Information',
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
  http: {
    id: 'http',
    title: 'HTTP Information',
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
  dns: {
    id: 'dns',
    title: 'DNS Information',
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
  tls: {
    id: 'tls',
    title: 'TLS Information',
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
  smtp: {
    id: 'smtp',
    title: 'SMTP Information',
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
  smb: {
    id: 'smb',
    title: 'SMB Information',
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
  ssh: {
    id: 'ssh',
    title: 'SSH Information',
    items: [
      {
        i: 'ssh.client.software_version',
        title: 'Client Software',
      },
      {
        i: 'ssh.server.software_version',
        title: 'Server Software',
      },
    ],
  },
};
