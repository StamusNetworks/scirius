import React from 'react';
import constants from 'ui/constants';
import moment from 'moment';
const { DATE_TIME_FORMAT } = constants;

const showMitreInfo = (mtn, mti) => {
  if (mtn && mti) {
    return `${mtn} ${mti}`;
  }
  if (mtn) {
    return mtn;
  }
  if (mti) {
    return mti;
  }
  return 'n/a';
};

const columns = {
  Alert: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Method', dataIndex: ['rawJson', 'alert', 'signature'] },
    { title: 'SignatureID', dataIndex: ['rawJson', 'alert', 'signature_id'] },
    { title: 'Category', dataIndex: ['rawJson', 'alert', 'category'] },
    {
      title: 'Mitre Tactic',
      render: ({ rawJson }) => {
        const { mitre_tactic_name: mtn, mitre_tactic_id: mti } = rawJson.alert?.metadata || {};
        return showMitreInfo(mtn, mti);
      },
    },
    {
      title: 'Mitre Technique',
      render: ({ rawJson }) => {
        const { mitre_technique_name: mtn, mitre_technique_id: mti } = rawJson.alert?.metadata || {};
        return showMitreInfo(mtn, mti);
      },
    },
  ],
  Http: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Host', dataIndex: ['rawJson', 'http', 'hostname'] },
    { title: 'URL', dataIndex: ['rawJson', 'http', 'url'] },
    { title: 'User Agent', dataIndex: ['rawJson', 'http', 'http_user_agent'] },
    { title: 'Status', dataIndex: ['rawJson', 'http', 'status'] },
    { title: 'HTTP Method', dataIndex: ['rawJson', 'http', 'http_method'] },
  ],
  Dns: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Protocol', dataIndex: ['rawJson', 'proto'] },
    { title: 'RRName', dataIndex: ['rawJson', 'dns', 'rrname'] },
    { title: 'RRType', dataIndex: ['rawJson', 'dns', 'rrtype'] },
    { title: 'RCode', dataIndex: ['rawJson', 'dns', 'rcode'] },
    { title: 'Type', dataIndex: ['rawJson', 'dns', 'type'] },
  ],
  Tls: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'SNI', dataIndex: ['rawJson', 'tls', 'sni'] },
    { title: 'Subject', dataIndex: ['rawJson', 'tls', 'subject'] },
    { title: 'Issuer', dataIndex: ['rawJson', 'tls', 'issuerdn'] },
  ],
  Ftp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Command', dataIndex: ['rawJson', 'ftp', 'command'] },
    { title: 'Command data', dataIndex: ['rawJson', 'ftp', 'command_data'] },
    { title: 'Reply', dataIndex: ['rawJson', 'ftp', 'reply'], render: val => val && val.map(str => <div>{str}</div>) },
    { title: 'Completion code', dataIndex: ['rawJson', 'ftp', 'completion_code'], render: val => val && val.map(str => <div>{str}</div>) },
  ],
  Smtp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Helo', dataIndex: ['rawJson', 'smtp', 'helo'] },
    { title: 'Mail from', dataIndex: ['rawJson', 'smtp', 'mail_from'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Mail to', dataIndex: ['rawJson', 'smtp', 'rcpt_to'], render: val => val && val.map(str => <div>{str.replace(/^<|>$/g, '')}</div>) },
    { title: 'Attachment', dataIndex: ['rawJson', 'email', 'attachment'], render: val => val && val.map(str => <div>{str}</div>) },
  ],
  Dcerpc: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Request', dataIndex: ['rawJson', 'dcerpc', 'request'] },
    { title: 'Response', dataIndex: ['rawJson', 'dcerpc', 'response'] },
    { title: 'Opnum', dataIndex: ['rawJson', 'dcerpc', 'req', 'opnum'] },
    { title: 'Uuid', dataIndex: ['rawJson', 'dcerpc', 'interfaces'], render: val => val && val.map(obj => <div>{obj.uuid}</div>) },
  ],
  Krb5: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Source IP', dataIndex: ['rawJson', 'src_ip'] },
    { title: 'Source port', dataIndex: ['rawJson', 'src_port'] },
    { title: 'Destination IP', dataIndex: ['rawJson', 'dest_ip'] },
    { title: 'Destination port', dataIndex: ['rawJson', 'dest_port'] },
    { title: 'Cname', dataIndex: ['rawJson', 'krb5', 'cname'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Message type', dataIndex: ['rawJson', 'krb5', 'msg_type'] },
    { title: 'Realm', dataIndex: ['rawJson', 'krb5', 'realm'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Sname', dataIndex: ['rawJson', 'krb5', 'sname'] },
    { title: 'Weak encryption', dataIndex: ['rawJson', 'krb5', 'weak_encryption'], render: bool => (bool ? 'Yes' : 'No') },
  ],
  Anomaly: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Protocol', dataIndex: ['rawJson', 'proto'] },
    { title: 'Event', dataIndex: ['rawJson', 'anomaly', 'event'] },
  ],
  Dhcp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Client MAC', dataIndex: ['rawJson', 'dhcp', 'client_mac'] },
    { title: 'DHCP type', dataIndex: ['rawJson', 'dhcp', 'dhcp_type'] },
    { title: 'DNS Servers', dataIndex: ['rawJson', 'dhcp', 'dns_servers'], render: ips => ips && ips.map(ip => <div>{ip}</div>) },
    { title: 'Hostname', dataIndex: ['rawJson', 'dhcp', 'hostname'] },
    { title: 'Client IP', dataIndex: ['rawJson', 'dhcp', 'client_ip'] },
    {
      title: 'Lease time',
      dataIndex: ['rawJson', 'dhcp', 'lease_time'],
      render: microseconds => moment(microseconds / 1000).format(DATE_TIME_FORMAT),
    },
  ],
  Flow: [
    { title: 'Start time', dataIndex: ['rawJson', 'flow', 'start'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'End time', dataIndex: ['rawJson', 'flow', 'end'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    {
      title: 'Duration',
      render: ({ rawJson }) => {
        if (rawJson.flow && rawJson.flow.end && rawJson.flow.start) {
          return moment.duration(moment(rawJson.flow.end).unix() - moment(rawJson.flow.start).unix(), 'seconds').humanize();
        }
        return 'n/a';
      },
    },
    { title: 'Bytes to server', dataIndex: ['rawJson', 'flow', 'bytes_toserver'] },
    { title: 'Bytes to client ', dataIndex: ['rawJson', 'flow', 'bytes_toclient'] },
    { title: 'Pkt to server', dataIndex: ['rawJson', 'flow', 'pkts_toserver'] },
    { title: 'Pkt to client', dataIndex: ['rawJson', 'flow', 'pkts_toclient'] },
  ],
  Smb: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Command', dataIndex: ['rawJson', 'smb', 'command'] },
    { title: 'Severity', dataIndex: ['rawJson', 'smb', 'ext_status', 'severity'] },
    { title: 'Interface', dataIndex: ['rawJson', 'smb', 'dcerpc', 'interface', 'name'] },
    { title: 'Endpoint', dataIndex: ['rawJson', 'smb', 'dcerpc', 'endpoint'] },
    { title: 'Uuid', dataIndex: ['rawJson', 'smb', 'dcerpc', 'interface', 'uuid'] },
    { title: 'Opnum', dataIndex: ['rawJson', 'smb', 'dcerpc', 'opnum'] },
    { title: 'Status', dataIndex: ['rawJson', 'smb', 'status'] },
    { title: 'Share', dataIndex: ['rawJson', 'smb', 'share'] },
    { title: 'Filename', dataIndex: ['rawJson', 'smb', 'filename'] },
    { title: 'Host', dataIndex: ['rawJson', 'smb', 'ntlmssp', 'host'] },
    { title: 'User', dataIndex: ['rawJson', 'smb', 'ntlmssp', 'user'] },
  ],
  Netflow: [
    { title: 'Start time', dataIndex: ['rawJson', 'netflow', 'start'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'End time', dataIndex: ['rawJson', 'netflow', 'end'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    {
      title: 'Duration',
      render: ({ rawJson }) => {
        if (rawJson.netflow && rawJson.netflow.end && rawJson.netflow.start) {
          return moment.duration(moment(rawJson.netflow.end).unix() - moment(rawJson.netflow.start).unix(), 'seconds').humanize();
        }
        return 'n/a';
      },
    },
    { title: 'Packets', dataIndex: ['rawJson', 'netflow', 'pkts'] },
    { title: 'Bytes', dataIndex: ['rawJson', 'netflow', 'bytes'] },
    { title: 'Age', dataIndex: ['rawJson', 'netflow', 'age'] },
  ],
  Fileinfo: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    {
      title: 'Mimetype',
      render: ({ rawJson }) => {
        if (rawJson.fileinfo && rawJson.fileinfo.mimetype) {
          return rawJson.fileinfo.mimetype;
        }
        if (rawJson.fileinfo && rawJson.fileinfo.type) {
          return rawJson.fileinfo.type;
        }
        return null;
      },
    },
    { title: 'Size', dataIndex: ['rawJson', 'fileinfo', 'size'] },
    { title: 'Filename', dataIndex: ['rawJson', 'fileinfo', 'filename'] },
    {
      title: 'Stored',
      render: ({ rawJson }) => {
        if (rawJson.fileinfo && !rawJson.fileinfo.stored) {
          return 'no';
        }
        if (rawJson.fileinfo && rawJson.fileinfo.stored) {
          return 'yes';
        }
        return null;
      },
    },
  ],
  Rdp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Event type', dataIndex: ['rawJson', 'rdp', 'event_type'] },
    { title: 'Client version', dataIndex: ['rawJson', 'rdp', 'client', 'version'] },
    { title: 'Client keyboard layout', dataIndex: ['rawJson', 'rdp', 'client', 'keyboard_layout'] },
    { title: 'Client name', dataIndex: ['rawJson', 'rdp', 'client', 'client_name'] },
  ],
  Snmp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Community', dataIndex: ['rawJson', 'snmp', 'community'] },
    { title: 'Pdu type', dataIndex: ['rawJson', 'snmp', 'pdu_type'] },
    { title: 'Vars', dataIndex: ['rawJson', 'snmp', 'vars'], render: val => val && val.map(str => <div>{str}</div>) },
    { title: 'Version', dataIndex: ['rawJson', 'snmp', 'version'] },
  ],
  Tftp: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'File', dataIndex: ['rawJson', 'tftp', 'file'] },
    { title: 'Mode', dataIndex: ['rawJson', 'tftp', 'mode'] },
    { title: 'Packet', dataIndex: ['rawJson', 'tftp', 'packet'] },
  ],
  Ssh: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Server proto version', dataIndex: ['rawJson', 'ssh', 'server', 'proto_version'] },
    { title: 'Server software versin', dataIndex: ['rawJson', 'ssh', 'server', 'software_version'] },
    { title: 'Client proto version', dataIndex: ['rawJson', 'ssh', 'client', 'proto_version'] },
    { title: 'Client software version', dataIndex: ['rawJson', 'ssh', 'client', 'software_version'] },
  ],
  Sip: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Version', dataIndex: ['rawJson', 'sip', 'version'] },
    { title: 'Code', dataIndex: ['rawJson', 'sip', 'code'] },
    { title: 'Method', dataIndex: ['rawJson', 'sip', 'method'] },
    { title: 'Uri', dataIndex: ['rawJson', 'sip', 'uri'] },
  ],
  Rfb: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Client protocol version, major', dataIndex: ['rawJson', 'rfb', 'client_protocol_version', 'major'] },
    { title: 'Server protocol version, major', dataIndex: ['rawJson', 'rfb', 'server_protocol_version', 'major'] },
    { title: 'Security type', dataIndex: ['rawJson', 'rfb', 'authentication', 'security_type'] },
    { title: 'Server security failure reason', dataIndex: ['rawJson', 'rfb', 'server_security_failure_reason'] },
  ],
  Mqtt: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Topic', dataIndex: ['rawJson', 'mqtt', 'publish', 'topic'] },
    { title: 'Username', dataIndex: ['rawJson', 'mqtt', 'connect', 'username'] },
    { title: 'Protocol strng', dataIndex: ['rawJson', 'mqtt', 'connect', 'protocol_string'] },
    { title: 'Protocol version', dataIndex: ['rawJson', 'mqtt', 'connect', 'protocol_version'] },
  ],
  Nfs: [
    { title: 'Timestamp', dataIndex: ['rawJson', '@timestamp'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Filename', dataIndex: ['rawJson', 'nfs', 'filename'] },
    { title: 'Procedure', dataIndex: ['rawJson', 'nfs', 'procedure'] },
    { title: 'Type', dataIndex: ['rawJson', 'nfs', 'type'] },
    { title: 'Version', dataIndex: ['rawJson', 'nfs', 'version'] },
  ],
};

export default columns;
