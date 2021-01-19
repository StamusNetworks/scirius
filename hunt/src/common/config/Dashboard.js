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
          title: 'Affected product',
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
          title: 'Attack target',
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
          title: 'Malware family',
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
          title: 'Signature severity',
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
          title: 'Lateral',
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
          title: 'Sources Network',
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
          title: 'Targets Network',
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
          title: 'FQDN Source',
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
          title: 'FQDN Destination',
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
          title: 'AS Number',
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
          title: 'AS Organization',
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
          title: 'Country Name',
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
          title: 'City Name',
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
        h: 270,
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
          title: 'Vlan',
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
        h: 170,
        x: 0,
        y: 782,
      },
    },
    http: {
      title: 'HTTP information',
      items: [
        {
          i: 'http.hostname',
          title: 'Hostname',
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
          title: 'URL',
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
          title: 'Useragent',
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
          title: 'Status',
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
          title: 'Referer',
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
        h: 370,
        x: 0,
        y: 1138,
      },
    },
    dns: {
      title: 'DNS information',
      items: [
        {
          i: 'dns.query.rrname',
          title: 'Name',
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
          title: 'Type',
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
          title: 'Server Name Indication',
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
          title: 'Subject DN',
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
          title: 'Issuer DN',
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
          title: 'Fingerprint',
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
          title: 'JA3 Hash',
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
          title: 'JA3 User-Agent',
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
          title: 'JA3S Hash',
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
        h: 270,
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
          title: 'Command',
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
          title: 'Status',
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
          title: 'Filename',
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
          title: 'Share',
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
          title: 'Client Software',
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
          title: 'Server Software',
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
