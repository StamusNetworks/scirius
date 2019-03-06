import store from 'store';
import find from 'lodash/find';

const storedMacroLayout = store.get('dashboardMacroLayout');

export const dashboard = {
    panel: {
        defaultHeadHeight: 67,
    },
    block: {
        defaultDimensions: {
            minW: 3,
            minH: 3,
            x: 0,
            y: 0,
            w: 3,
            h: 3,
        },
        defaultItemHeight: 41,
        defaultHeadHeight: 70,
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
                            w: 9, h: 22, x: 15, y: 0
                        },
                        md: {
                            w: 9, h: 22, x: 15, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'alert.metadata.attack_target',
                    title: 'Attack target',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 15, x: 7, y: 0
                        },
                        md: {
                            w: 8, h: 15, x: 7, y: 0
                        },
                        sm: {
                            w: 8, h: 15, x: 0, y: 22
                        },
                        xs: {
                            w: 4, h: 15, x: 4, y: 0
                        },
                    },
                }, {
                    i: 'alert.metadata.malware_family',
                    title: 'Malware family',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 12, x: 24, y: 0
                        },
                        md: {
                            w: 7, h: 12, x: 0, y: 18
                        },
                        sm: {
                            w: 8, h: 12, x: 8, y: 18
                        },
                        xs: {
                            w: 4, h: 12, x: 4, y: 15
                        },
                    },
                }, {
                    i: 'alert.metadata.signature_severity',
                    title: 'Signature severity',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 7, h: 18, x: 0, y: 0
                        },
                        md: {
                            w: 7, h: 18, x: 0, y: 0
                        },
                        sm: {
                            w: 8, h: 18, x: 8, y: 0
                        },
                        xs: {
                            w: 4, h: 18, x: 0, y: 22
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'metadata' }) || {
                w: 1, h: 356, x: 0, y: 426
            },
            loaded: false
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
                            w: 11, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 7, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                },
                {
                    i: 'alert.category',
                    title: 'Categories',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 9, h: 22, x: 11, y: 0
                        },
                        md: {
                            w: 7, h: 22, x: 7, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 6, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 0
                        },
                    },
                },
                {
                    i: 'alert.severity',
                    title: 'Severities',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 5, h: 15, x: 20, y: 0
                        },
                        md: {
                            w: 4, h: 15, x: 14, y: 0
                        },
                        sm: {
                            w: 3, h: 15, x: 0, y: 22
                        },
                        xs: {
                            w: 4, h: 15, x: 0, y: 22
                        },
                    },
                },
                {
                    i: 'host',
                    title: 'Probes',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 7, h: 15, x: 25, y: 0
                        },
                        md: {
                            w: 6, h: 15, x: 18, y: 0
                        },
                        sm: {
                            w: 5, h: 15, x: 11, y: 0
                        },
                        xs: {
                            w: 4, h: 15, x: 4, y: 22
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'basic' }) || {
                w: 1, h: 356, x: 0, y: 0
            },
            loaded: false
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
                            w: 8, h: 222, x: 0, y: 0
                        },
                        md: {
                            w: 8, h: 122, x: 8, y: 0
                        },
                        sm: {
                            w: 8, h: 222, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 222, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'alert.target.ip',
                    title: 'Targets',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 22, x: 8, y: 0
                        },
                        md: {
                            w: 7, h: 12, x: 7, y: 0
                        },
                        sm: {
                            w: 8, h: 12, x: 8, y: 0
                        },
                        xs: {
                            w: 4, h: 12, x: 4, y: 0
                        },
                    },
                }, {
                    i: 'alert.lateral',
                    title: 'Lateral',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 7, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 1, y: 0
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'organizational' }) || {
                w: 1, h: 70, x: 0, y: 356
            },
            loaded: false
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
                            w: 7, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'dest_ip',
                    title: 'Destinations IP',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 7, h: 22, x: 7, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 6, y: 0
                        },
                        sm: {
                            w: 6, h: 22, x: 5, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 0
                        },
                    }
                }, {
                    i: 'src_port',
                    title: 'Source Ports',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 6, h: 22, x: 14, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 12, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 11, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 22
                        },
                    }
                }, {
                    i: 'dest_port',
                    title: 'Destinations Ports',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 6, h: 22, x: 20, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 18, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 0, y: 22
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 22
                        },
                    }
                }, {
                    i: 'proto',
                    title: 'IP Protocols',
                    position: 4,
                    data: null,
                    dimensions: {
                        lg: {
                            w: 6, h: 9, x: 26, y: 0
                        },
                        md: {
                            w: 6, h: 9, x: 0, y: 22
                        },
                        sm: {
                            w: 6, h: 9, x: 5, y: 22
                        },
                        xs: {
                            w: 4, h: 9, x: 0, y: 44
                        },
                    }
                }, {
                    i: 'vlan',
                    title: 'Vlan',
                    position: 5,
                    data: null,
                    dimensions: {
                        lg: {
                            w: 7, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 5, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'ip' }) || {
                w: 1, h: 356, x: 0, y: 782
            },
            loaded: false
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
                            w: 9, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 6, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'http.url',
                    title: 'URL',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 9, h: 22, x: 9, y: 0
                        },
                        md: {
                            w: 6, h: 22, x: 6, y: 0
                        },
                        sm: {
                            w: 6, h: 22, x: 6, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 0
                        },
                    },
                }, {
                    i: 'http.http_user_agent',
                    title: 'Useragent',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 9, h: 12, x: 23, y: 0
                        },
                        md: {
                            w: 6, h: 12, x: 12, y: 0
                        },
                        sm: {
                            w: 12, h: 12, x: 0, y: 22
                        },
                        xs: {
                            w: 4, h: 12, x: 0, y: 22
                        },
                    },
                }, {
                    i: 'http.status',
                    title: 'Status',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 5, h: 18, x: 18, y: 0
                        },
                        md: {
                            w: 6, h: 18, x: 18, y: 0
                        },
                        sm: {
                            w: 4, h: 18, x: 12, y: 0
                        },
                        xs: {
                            w: 4, h: 18, x: 4, y: 22
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'http' }) || {
                w: 1, h: 356, x: 0, y: 1138
            },
            loaded: false
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
                            w: 9, h: 12, x: 0, y: 0
                        },
                        md: {
                            w: 10, h: 12, x: 0, y: 0
                        },
                        sm: {
                            w: 8, h: 12, x: 0, y: 0
                        },
                        xs: {
                            w: 5, h: 12, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'dns.query.rrtype',
                    title: 'Type',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 9, h: 9, x: 9, y: 0
                        },
                        md: {
                            w: 9, h: 9, x: 10, y: 0
                        },
                        sm: {
                            w: 8, h: 9, x: 8, y: 0
                        },
                        xs: {
                            w: 3, h: 9, x: 5, y: 0
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'dns' }) || {
                w: 1, h: 226, x: 0, y: 1494
            },
            loaded: false
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
                            w: 10, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 7, h: 22, x: 0, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'tls.subject',
                    title: 'Subject DN',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 11, h: 22, x: 10, y: 0
                        },
                        md: {
                            w: 8, h: 22, x: 7, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 8, y: 0
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 0
                        },
                    },
                }, {
                    i: 'tls.issuerdn',
                    title: 'Issuer DN',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 11, h: 22, x: 21, y: 0
                        },
                        md: {
                            w: 9, h: 22, x: 15, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 0, y: 22
                        },
                        xs: {
                            w: 4, h: 22, x: 0, y: 22
                        },
                    },
                }, {
                    i: 'tls.fingerprint',
                    title: 'Fingerprint',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 10, h: 22, x: 0, y: 22
                        },
                        md: {
                            w: 12, h: 22, x: 0, y: 22
                        },
                        sm: {
                            w: 8, h: 22, x: 8, y: 22
                        },
                        xs: {
                            w: 4, h: 22, x: 4, y: 22
                        },
                    },
                }, {
                    i: 'tls.ja3.hash',
                    title: 'JA3 Hash',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 11, h: 12, x: 10, y: 22
                        },
                        md: {
                            w: 10, h: 12, x: 12, y: 22
                        },
                        sm: {
                            w: 8, h: 12, x: 0, y: 44
                        },
                        xs: {
                            w: 8, h: 12, x: 0, y: 44
                        },
                    },
                }, {
                    i: 'tls.ja3.agent',
                    title: 'JA3 User-Agent',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 11, h: 12, x: 10, y: 22
                        },
                        md: {
                            w: 10, h: 12, x: 12, y: 22
                        },
                        sm: {
                            w: 8, h: 12, x: 0, y: 44
                        },
                        xs: {
                            w: 8, h: 12, x: 0, y: 44
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'tls' }) || {
                w: 1, h: 642, x: 0, y: 1720
            },
            loaded: false
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
                            w: 11, h: 9, x: 0, y: 0
                        },
                        md: {
                            w: 8, h: 9, x: 0, y: 0
                        },
                        sm: {
                            w: 6, h: 9, x: 0, y: 0
                        },
                        xs: {
                            w: 8, h: 9, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'smtp.rcpt_to',
                    title: 'RCPT To',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 10, h: 9, x: 11, y: 0
                        },
                        md: {
                            w: 8, h: 9, x: 8, y: 0
                        },
                        sm: {
                            w: 5, h: 9, x: 6, y: 0
                        },
                        xs: {
                            w: 8, h: 9, x: 0, y: 9
                        },
                    },
                }, {
                    i: 'smtp.helo',
                    title: 'Helo',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 11, h: 9, x: 21, y: 0
                        },
                        md: {
                            w: 8, h: 9, x: 16, y: 0
                        },
                        sm: {
                            w: 5, h: 9, x: 11, y: 0
                        },
                        xs: {
                            w: 8, h: 9, x: 0, y: 18
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'smtp' }) || {
                w: 1, h: 187, x: 0, y: 2362
            },
            loaded: false
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
                            w: 8, h: 22, x: 0, y: 0
                        },
                        md: {
                            w: 8, h: 12, x: 0, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 0, y: 0
                        },
                        xs: {
                            w: 8, h: 22, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'smb.status',
                    title: 'Status',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 22, x: 8, y: 0
                        },
                        md: {
                            w: 8, h: 12, x: 8, y: 0
                        },
                        sm: {
                            w: 8, h: 12, x: 8, y: 0
                        },
                        xs: {
                            w: 8, h: 12, x: 0, y: 1
                        },
                    },
                }, {
                    i: 'smb.filename',
                    title: 'Filename',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 22, x: 16, y: 0
                        },
                        md: {
                            w: 8, h: 22, x: 16, y: 0
                        },
                        sm: {
                            w: 8, h: 22, x: 0, y: 1
                        },
                        xs: {
                            w: 8, h: 22, x: 0, y: 2
                        },
                    },
                }, {
                    i: 'smb.share',
                    title: 'Share',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 8, h: 22, x: 24, y: 0
                        },
                        md: {
                            w: 8, h: 22, x: 0, y: 1
                        },
                        sm: {
                            w: 8, h: 22, x: 8, y: 1
                        },
                        xs: {
                            w: 8, h: 22, x: 0, y: 3
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'smb' }) || {
                w: 1, h: 70, x: 0, y: 2549
            },
            loaded: false
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
                            w: 14, h: 9, x: 0, y: 0
                        },
                        md: {
                            w: 12, h: 9, x: 0, y: 0
                        },
                        sm: {
                            w: 8, h: 9, x: 0, y: 0
                        },
                        xs: {
                            w: 4, h: 9, x: 0, y: 0
                        },
                    },
                }, {
                    i: 'ssh.server.software_version',
                    title: 'Server Software',
                    data: null,
                    dimensions: {
                        lg: {
                            w: 18, h: 15, x: 14, y: 0
                        },
                        md: {
                            w: 12, h: 15, x: 12, y: 0
                        },
                        sm: {
                            w: 8, h: 15, x: 8, y: 0
                        },
                        xs: {
                            w: 4, h: 15, x: 4, y: 0
                        },
                    },
                }
            ],
            dimensions: find(storedMacroLayout, { i: 'ssh' }) || {
                w: 1, h: 265, x: 0, y: 2619
            },
            loaded: false
        },
    },
};
