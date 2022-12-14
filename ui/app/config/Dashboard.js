export const dashboard = {
  basic: {
    title: 'Basic Information',
    items: [
      {
        i: 'alert.signature',
        title: 'Signatures',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
      {
        i: 'alert.category',
        title: 'Categories',
        dimensions: {
          xxl: 7,
          xl: 7,
        },
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
        dimensions: {
          xxl: 4,
          xl: 4,
        },
      },
      {
        i: 'host',
        title: 'Probes',
        dimensions: {
          xxl: 5,
          xl: 5,
        },
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
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.target.ip',
        title: 'Targets',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.lateral',
        title: 'Laterals',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.source.net_info_agg',
        title: 'Sources Networks',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.target.net_info_agg',
        title: 'Targets Networks',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'fqdn.src',
        title: 'FQDN Sources',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'fqdn.dest',
        title: 'FQDN Destinations',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'geoip.provider.autonomous_system_number',
        title: 'AS Numbers',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'geoip.provider.autonomous_system_organization',
        title: 'AS Organizations',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'geoip.country_name',
        title: 'Country Names',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'geoip.city_name',
        title: 'City Names',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
    ],
  },
  metadata: {
    title: 'Metadata',
    items: [
      {
        i: 'alert.metadata.signature_severity',
        title: 'Signature Severities',
        dimensions: {
          xxl: 5,
          xl: 5,
        },
      },
      {
        i: 'alert.metadata.attack_target',
        title: 'Attack Targets',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.metadata.affected_product',
        title: 'Affected Products',
        dimensions: {
          xxl: 7,
          xl: 7,
        },
      },
      {
        i: 'alert.metadata.malware_family',
        title: 'Malware Families',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
    ],
  },
  mitre: {
    title: 'MITRE ATT&CK Information',
    items: [
      {
        i: 'alert.metadata.mitre_tactic_id',
        title: 'Tactic IDs',
        dimensions: {
          xxl: 5,
          xl: 5,
        },
      },
      {
        i: 'alert.metadata.mitre_tactic_name',
        title: 'Tactic Names',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.metadata.mitre_technique_id',
        title: 'Technique IDs',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'alert.metadata.mitre_technique_name',
        title: 'Technique Names',
        dimensions: {
          xxl: 7,
          xl: 7,
        },
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
        dimensions: {
          xxl: 5,
          xl: 6,
        },
      },
      {
        i: 'dest_ip',
        title: 'Destinations IP',
        dimensions: {
          xxl: 5,
          xl: 6,
        },
      },
      {
        i: 'src_port',
        title: 'Source Ports',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
      {
        i: 'dest_port',
        title: 'Destinations Ports',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
      {
        i: 'proto',
        title: 'IP Protocols',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
      {
        i: 'vlan',
        title: 'Vlans',
        dimensions: {
          xxl: 5,
          xl: 6,
        },
      },
      {
        i: 'tunnel.src_ip',
        title: 'Tunnel Source IPs',
        dimensions: {
          xxl: 5,
          xl: 6,
        },
      },
      {
        i: 'tunnel.dest_ip',
        title: 'Tunnel Destinations IP',
        dimensions: {
          xxl: 5,
          xl: 6,
        },
      },
      {
        i: 'tunnel.proto',
        title: 'Tunnel Protocols',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
      {
        i: 'tunnel.depth',
        title: 'Tunnel Depths',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
    ],
  },
  http: {
    id: 'http',
    title: 'HTTP information',
    items: [
      {
        i: 'http.hostname',
        title: 'Hostnames',
        dimensions: {
          xxl: 7,
          xl: 6,
        },
      },
      {
        i: 'http.url',
        title: 'URLs',
        dimensions: {
          xxl: 7,
          xl: 6,
        },
      },
      {
        i: 'http.status',
        title: 'Statuses',
        dimensions: {
          xxl: 3,
          xl: 6,
        },
      },
      {
        i: 'http.http_user_agent',
        title: 'Useragents',
        dimensions: {
          xxl: 7,
          xl: 6,
        },
      },
      {
        i: 'http.http_refer',
        title: 'Referrers',
        dimensions: {
          xxl: 7,
          xl: 6,
        },
      },
    ],
  },
  dns: {
    id: 'dns',
    title: 'DNS information',
    items: [
      {
        i: 'dns.query.rrname',
        title: 'Names',
        dimensions: {
          xxl: 9,
          xl: 12,
        },
      },
      {
        i: 'dns.query.rrtype',
        title: 'Types',
        dimensions: {
          xxl: 5,
          xl: 12,
        },
      },
    ],
  },
  tls: {
    id: 'tls',
    title: 'TLS information',
    items: [
      {
        i: 'tls.sni',
        title: 'Server Names Indication',
        dimensions: {
          xxl: 8,
          xl: 7,
        },
      },
      {
        i: 'tls.subject',
        title: 'Subject DNs',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
      {
        i: 'tls.issuerdn',
        title: 'Issuers DN',
        dimensions: {
          xxl: 8,
          xl: 9,
        },
      },
      {
        i: 'tls.fingerprint',
        title: 'Fingerprints',
        dimensions: {
          xxl: 8,
          xl: 12,
        },
      },
      {
        i: 'tls.ja3.hash',
        title: 'JA3 Hashes',
        dimensions: {
          xxl: 8,
          xl: 12,
        },
      },
      {
        i: 'tls.ja3.agent',
        title: 'JA3 User-Agents',
        dimensions: {
          xxl: 8,
          xl: 12,
        },
      },
      {
        i: 'tls.ja3s.hash',
        title: 'JA3S Hashes',
        dimensions: {
          xxl: 8,
          xl: 12,
        },
      },
    ],
  },
  smtp: {
    id: 'smtp',
    title: 'SMTP information',
    items: [
      {
        i: 'smtp.mail_from',
        title: 'Mail From',
        dimensions: {
          xxl: 9,
          xl: 9,
        },
      },
      {
        i: 'smtp.rcpt_to',
        title: 'RCPT To',
        dimensions: {
          xxl: 6,
          xl: 6,
        },
      },
      {
        i: 'smtp.helo',
        title: 'Helo',
        dimensions: {
          xxl: 9,
          xl: 9,
        },
      },
    ],
  },
  smb: {
    id: 'smb',
    title: 'SMB information',
    items: [
      {
        i: 'smb.command',
        title: 'Commands',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
      {
        i: 'smb.status',
        title: 'Statuses',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
      {
        i: 'smb.filename',
        title: 'Filenames',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
      {
        i: 'smb.share',
        title: 'Shares',
        dimensions: {
          xxl: 8,
          xl: 8,
        },
      },
    ],
  },
  ssh: {
    id: 'ssh',
    title: 'SSH information',
    items: [
      {
        i: 'ssh.client.software_version',
        title: 'Client Softwares',
        dimensions: {
          xxl: 12,
          xl: 12,
        },
      },
      {
        i: 'ssh.server.software_version',
        title: 'Server Softwares',
        dimensions: {
          xxl: 12,
          xl: 12,
        },
      },
    ],
  },
};
