const FiltersDropdownItems = {
  EVENT: [
    { id: 'ip' },
    { id: 'host' },
    { id: 'port' },
    { id: 'alert.signature' },
    { id: 'alert.signature_id' },
    { id: 'es_filter' },
    {
      id: 'protocol',
      label: 'Protocol',
      children: [
        {
          id: 'dns',
          label: 'DNS',
          children: [{ id: 'dns.query.rrname' }, { id: 'dns.query.rrtype' }],
        },
        {
          id: 'http',
          label: 'HTTP',
          children: [
            { id: 'http.http_user_agent' },
            { id: 'http.hostname' },
            { id: 'http.url' },
            { id: 'http.status' },
            { id: 'http.http_method' },
            { id: 'http.http_content_type' },
            { id: 'http.length' },
          ],
        },
        {
          id: 'smtp',
          label: 'SMTP',
          children: [{ id: 'smtp.mail_from' }, { id: 'smtp.rcpt_to' }, { id: 'smtp.helo' }],
        },
        {
          id: 'smb',
          label: 'SMB',
          children: [{ id: 'smb.command' }, { id: 'smb.status' }, { id: 'smb.filename' }, { id: 'smb.share' }],
        },
        {
          id: 'ssh',
          label: 'SSH',
          children: [
            { id: 'ssh.client.software_version' },
            { id: 'ssh.client.proto_version' },
            { id: 'ssh.server.software_version' },
            { id: 'ssh.server.proto_version' },
          ],
        },
        {
          id: 'tls',
          label: 'TLS',
          children: [
            { id: 'tls.subject' },
            { id: 'tls.issuerdn' },
            { id: 'tls.sni' },
            { id: 'tls.version' },
            { id: 'tls.fingerprint' },
            { id: 'tls.serial' },
            { id: 'tls.ja3.hash' },
            { id: 'tls.ja3s.hash' },
          ],
        },
      ],
    },
  ],
  SIGNATURE: [{ id: 'hits_min' }, { id: 'hits_max' }, { id: 'msg' }, { id: 'content' }],
  HISTORY: [],
};

export default FiltersDropdownItems;
