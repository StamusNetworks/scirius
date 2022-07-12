export const dashboard = {
  panel: {
    defaultHeadHeight: 67,
  },
  block: {
    defaultDimensions: {
      minW: 3,
      minH: 7,
      x: 0,
      y: 0,
      w: 3,
      h: 7,
    },
    defaultItemHeight: 33,
    defaultHeadHeight: 50,
  },
  sections: {
    metadata: {
      title: 'Metadata',
      items: [
        {
          i: 'alert.metadata.affected_product',
          title: 'Affected products',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 15,
              y: 0,
            },
            md: {
              w: 9,
              h: 7,
              x: 15,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'alert.metadata.attack_target',
          title: 'Attack targets',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 7,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 7,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'alert.metadata.malware_family',
          title: 'Malware families',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 24,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 18,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 18,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 15,
            },
          },
        },
        {
          i: 'alert.metadata.signature_severity',
          title: 'Signature severities',
          data: null,
          dimensions: {
            lg: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 22,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 426,
      },
    },
    mitre: {
      title: 'MITRE ATT&CK Information',
      items: [
        {
          i: 'alert.metadata.mitre_tactic_id',
          title: 'Tactic IDs',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 15,
              y: 0,
            },
            md: {
              w: 9,
              h: 7,
              x: 15,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'alert.metadata.mitre_tactic_name',
          title: 'Tactic Names',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 7,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 7,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'alert.metadata.mitre_technique_id',
          title: 'Technique IDs',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 24,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 18,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 18,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 15,
            },
          },
        },
        {
          i: 'alert.metadata.mitre_technique_name',
          title: 'Technique Names',
          data: null,
          dimensions: {
            lg: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 22,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 426,
      },
    },
    basic: {
      title: 'Basic Information',
      items: [
        {
          i: 'alert.signature',
          title: 'Signatures',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'alert.category',
          title: 'Categories',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 11,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 7,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 6,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'alert.severity',
          title: 'Severities',
          data: null,
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
            lg: {
              w: 5,
              h: 7,
              x: 20,
              y: 0,
            },
            md: {
              w: 4,
              h: 7,
              x: 14,
              y: 0,
            },
            sm: {
              w: 3,
              h: 7,
              x: 0,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 22,
            },
          },
        },
        {
          i: 'host',
          title: 'Probes',
          data: null,
          dimensions: {
            lg: {
              w: 7,
              h: 7,
              x: 25,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 22,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 0,
      },
    },
    organizational: {
      title: 'Organizational Information',
      items: [
        {
          i: 'alert.source.ip',
          title: 'Sources',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'alert.target.ip',
          title: 'Targets',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'alert.lateral',
          title: 'Laterals',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 14,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 14,
            },
          },
        },
        {
          i: 'alert.source.net_info_agg',
          title: 'Sources Networks',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 7,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 8,
            },
          },
        },
        {
          i: 'alert.target.net_info_agg',
          title: 'Targets Networks',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 24,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 7,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 7,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 8,
            },
          },
        },
        {
          i: 'fqdn.src',
          title: 'FQDN Sources',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'fqdn.dest',
          title: 'FQDN Destinations',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 7,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 8,
            },
          },
        },
        {
          i: 'geoip.provider.autonomous_system_number',
          title: 'AS Numbers',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 24,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 7,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 7,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 8,
            },
          },
        },
        {
          i: 'geoip.provider.autonomous_system_organization',
          title: 'AS Organizations',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 14,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 14,
            },
          },
        },
        {
          i: 'geoip.country_name',
          title: 'Country Names',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'geoip.city_name',
          title: 'City Names',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 7,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 8,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 370,
        x: 0,
        y: 356,
      },
    },
    ip: {
      title: 'IP Information',
      items: [
        {
          i: 'src_ip',
          title: 'Sources IP',
          data: null,
          dimensions: {
            lg: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'dest_ip',
          title: 'Destinations IP',
          data: null,
          dimensions: {
            lg: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 5,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'src_port',
          title: 'Source Ports',
          data: null,
          dimensions: {
            lg: {
              w: 5,
              h: 7,
              x: 12,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 19,
            },
          },
        },
        {
          i: 'dest_port',
          title: 'Destinations Ports',
          data: null,
          dimensions: {
            lg: {
              w: 5,
              h: 7,
              x: 17,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 17,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 19,
            },
          },
        },
        {
          i: 'proto',
          title: 'IP Protocols',
          position: 4,
          data: null,
          dimensions: {
            lg: {
              w: 4,
              h: 7,
              x: 22,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 17,
            },
            sm: {
              w: 6,
              h: 7,
              x: 5,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 38,
            },
          },
        },
        {
          i: 'vlan',
          title: 'Vlans',
          position: 5,
          data: null,
          dimensions: {
            lg: {
              w: 6,
              h: 7,
              x: 26,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 38,
            },
          },
        },
        {
          i: 'tunnel.src_ip',
          title: 'Tunnel Sources IP',
          data: null,
          dimensions: {
            lg: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'tunnel.dest_ip',
          title: 'Tunnel Destinations IP',
          data: null,
          dimensions: {
            lg: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 5,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'tunnel.proto',
          title: 'Tunnel Protocols',
          data: null,
          dimensions: {
            lg: {
              w: 5,
              h: 7,
              x: 12,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 19,
            },
          },
        },
        {
          i: 'tunnel.depth',
          title: 'Tunnel Depths',
          data: null,
          dimensions: {
            lg: {
              w: 5,
              h: 7,
              x: 17,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 17,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 19,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 270,
        x: 0,
        y: 782,
      },
    },
    http: {
      title: 'HTTP information',
      items: [
        {
          i: 'http.hostname',
          title: 'Hostnames',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'http.url',
          title: 'URLs',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 9,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 6,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'http.http_user_agent',
          title: 'Useragents',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 23,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 51,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 22,
            },
          },
        },
        {
          i: 'http.status',
          title: 'Statuses',
          data: null,
          dimensions: {
            lg: {
              w: 5,
              h: 7,
              x: 18,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 18,
              y: 0,
            },
            sm: {
              w: 4,
              h: 7,
              x: 12,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 22,
            },
          },
        },
        {
          i: 'http.http_refer',
          title: 'Referers',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 470,
        x: 0,
        y: 1138,
      },
    },
    dns: {
      title: 'DNS information',
      items: [
        {
          i: 'dns.query.rrname',
          title: 'Names',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 12,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'dns.query.rrtype',
          title: 'Types',
          data: null,
          dimensions: {
            lg: {
              w: 9,
              h: 7,
              x: 9,
              y: 0,
            },
            md: {
              w: 12,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 1494,
      },
    },
    tls: {
      title: 'TLS information',
      items: [
        {
          i: 'tls.sni',
          title: 'Server Names Indication',
          data: null,
          dimensions: {
            lg: {
              w: 10,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 7,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'tls.subject',
          title: 'Subjects DN',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 10,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 7,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
        {
          i: 'tls.issuerdn',
          title: 'Issuers DN',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 21,
              y: 0,
            },
            md: {
              w: 9,
              h: 7,
              x: 15,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 22,
            },
          },
        },
        {
          i: 'tls.fingerprint',
          title: 'Fingerprints',
          data: null,
          dimensions: {
            lg: {
              w: 10,
              h: 7,
              x: 0,
              y: 22,
            },
            md: {
              w: 12,
              h: 7,
              x: 0,
              y: 22,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 22,
            },
          },
        },
        {
          i: 'tls.ja3.hash',
          title: 'JA3 Hashes',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 10,
              y: 22,
            },
            md: {
              w: 12,
              h: 7,
              x: 12,
              y: 4,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 44,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 44,
            },
          },
        },
        {
          i: 'tls.ja3.agent',
          title: 'JA3 User-Agents',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 21,
              y: 6,
            },
            md: {
              w: 12,
              h: 7,
              x: 0,
              y: 8,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 8,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 44,
            },
          },
        },
        {
          i: 'tls.ja3s.hash',
          title: 'JA3S Hashes',
          data: null,
          dimensions: {
            lg: {
              w: 10,
              h: 7,
              x: 0,
              y: 22,
            },
            md: {
              w: 12,
              h: 7,
              x: 0,
              y: 22,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 22,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 22,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 370,
        x: 0,
        y: 1720,
      },
    },
    smtp: {
      title: 'SMTP information',
      items: [
        {
          i: 'smtp.mail_from',
          title: 'Mail From',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 6,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'smtp.rcpt_to',
          title: 'RCPT To',
          data: null,
          dimensions: {
            lg: {
              w: 10,
              h: 7,
              x: 11,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 6,
              y: 0,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 9,
            },
          },
        },
        {
          i: 'smtp.helo',
          title: 'Helo',
          data: null,
          dimensions: {
            lg: {
              w: 11,
              h: 7,
              x: 21,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            sm: {
              w: 5,
              h: 7,
              x: 11,
              y: 0,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 18,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 2362,
      },
    },
    smb: {
      title: 'SMB information',
      items: [
        {
          i: 'smb.command',
          title: 'Commands',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'smb.status',
          title: 'Statuses',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 1,
            },
          },
        },
        {
          i: 'smb.filename',
          title: 'Filenames',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 16,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 1,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 2,
            },
          },
        },
        {
          i: 'smb.share',
          title: 'Shares',
          data: null,
          dimensions: {
            lg: {
              w: 8,
              h: 7,
              x: 24,
              y: 0,
            },
            md: {
              w: 8,
              h: 7,
              x: 0,
              y: 1,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 1,
            },
            xs: {
              w: 8,
              h: 7,
              x: 0,
              y: 3,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 2549,
      },
    },
    ssh: {
      title: 'SSH information',
      items: [
        {
          i: 'ssh.client.software_version',
          title: 'Client Softwares',
          position: 1,
          data: null,
          dimensions: {
            lg: {
              w: 14,
              h: 7,
              x: 0,
              y: 0,
            },
            md: {
              w: 12,
              h: 7,
              x: 0,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 0,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 0,
              y: 0,
            },
          },
        },
        {
          i: 'ssh.server.software_version',
          title: 'Server Softwares',
          data: null,
          dimensions: {
            lg: {
              w: 18,
              h: 7,
              x: 14,
              y: 0,
            },
            md: {
              w: 12,
              h: 7,
              x: 12,
              y: 0,
            },
            sm: {
              w: 8,
              h: 7,
              x: 8,
              y: 0,
            },
            xs: {
              w: 4,
              h: 7,
              x: 4,
              y: 0,
            },
          },
        },
      ],
      dimensions: {
        w: 1,
        h: 170,
        x: 0,
        y: 2619,
      },
    },
  },
};
