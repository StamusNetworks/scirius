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
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Signature', dataIndex: ['alert', 'signature'] },
    { title: 'SignatureID', dataIndex: ['alert', 'signature_id'] },
    { title: 'Category', dataIndex: ['alert', 'category'] },
    {
      title: 'Mitre Tactic',
      render: val => {
        const { mitre_tactic_name: mtn, mitre_tactic_id: mti } = val.alert?.metadata || {};
        return showMitreInfo(mtn, mti);
      },
    },
    {
      title: 'Mitre Technique',
      render: val => {
        const { mitre_technique_name: mtn, mitre_technique_id: mti } = val.alert?.metadata || {};
        return showMitreInfo(mtn, mti);
      },
    },
  ],
  Http: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Host', dataIndex: ['http', 'hostname'] },
    { title: 'URL', dataIndex: ['http', 'url'] },
    { title: 'User Agent', dataIndex: ['http', 'http_user_agent'] },
    { title: 'Status', dataIndex: ['http', 'status'] },
    { title: 'HTTP Method', dataIndex: ['http', 'http_method'] },
  ],
  Dns: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Protocol', dataIndex: ['proto'] },
    { title: 'RRName', dataIndex: ['dns', 'rrname'] },
    { title: 'RRType', dataIndex: ['dns', 'rrtype'] },
    { title: 'RCode', dataIndex: ['dns', 'rcode'] },
    { title: 'Type', dataIndex: ['dns', 'type'] },
  ],
  Tls: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'SNI', dataIndex: ['tls', 'sni'] },
    { title: 'Subject', dataIndex: ['tls', 'subject'] },
    { title: 'Issuer', dataIndex: ['tls', 'issuerdn'] },
  ],
  Ftp: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Command', dataIndex: ['ftp', 'command'] },
    { title: 'Command data', dataIndex: ['ftp', 'command_data'] },
    { title: 'Reply', dataIndex: ['ftp', 'reply'], render: val => val && val.map(str => <div>{str}</div>) },
    { title: 'Completion code', dataIndex: ['ftp', 'completion_code'], render: val => val && val.map(str => <div>{str}</div>) },
  ],
  Smtp: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Helo', dataIndex: ['smtp', 'helo'] },
    { title: 'Mail from', dataIndex: ['smtp', 'mail_from'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Mail to', dataIndex: ['smtp', 'rcpt_to'], render: val => val && val.map(str => <div>{str.replace(/^<|>$/g, '')}</div>) },
    { title: 'Attachment', dataIndex: ['email', 'attachment'], render: val => val && val.map(str => <div>{str}</div>) },
  ],
  Dcerpc: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Request', dataIndex: ['dcerpc', 'request'] },
    { title: 'Response', dataIndex: ['dcerpc', 'response'] },
    { title: 'Opnum', dataIndex: ['dcerpc', 'req', 'opnum'] },
    { title: 'Uuid', dataIndex: ['dcerpc', 'interfaces'], render: val => val && val.map(obj => <div>{obj.uuid}</div>) },
  ],
  Krb5: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Source IP', dataIndex: ['src_ip'] },
    { title: 'Source port', dataIndex: ['src_port'] },
    { title: 'Destination IP', dataIndex: ['dest_ip'] },
    { title: 'Destination port', dataIndex: ['dest_port'] },
    { title: 'Cname', dataIndex: ['krb5', 'cname'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Message type', dataIndex: ['krb5', 'msg_type'] },
    { title: 'Realm', dataIndex: ['krb5', 'realm'], render: val => val && val.replace(/^<|>$/g, '') },
    { title: 'Sname', dataIndex: ['krb5', 'sname'] },
    { title: 'Weak encryption', dataIndex: ['krb5', 'weak_encryption'], render: bool => (bool ? 'Yes' : 'No') },
  ],
  Flow: [
    { title: 'Start time', dataIndex: ['flow', 'start'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'End time', dataIndex: ['flow', 'end'], render: val => moment(val).format(DATE_TIME_FORMAT) },
    {
      title: 'Duration',
      render: val => {
        if (val.flow && val.flow.end && val.flow.start) {
          return moment.duration(moment(val.flow.end).unix() - moment(val.flow.start).unix(), 'seconds').humanize();
        }
        return 'n/a';
      },
    },
    { title: 'Bytes to server', dataIndex: ['flow', 'bytes_toserver'] },
    { title: 'Bytes to client ', dataIndex: ['flow', 'bytes_toclient'] },
    { title: 'Pkt to server', dataIndex: ['flow', 'pkts_toserver'] },
    { title: 'Pkt to client', dataIndex: ['flow', 'pkts_toclient'] },
  ],
  Smb: [
    { title: 'Timestamp', dataIndex: '@timestamp', render: val => moment(val).format(DATE_TIME_FORMAT) },
    { title: 'Command', dataIndex: ['smb', 'command'] },
    { title: 'Severity', dataIndex: ['smb', 'ext_status', 'severity'] },
    { title: 'Interface', dataIndex: ['smb', 'dcerpc', 'interface'] },
    { title: 'Endpoint', dataIndex: ['smb', 'dcerpc', 'endpoint'] },
    { title: 'Uuid', dataIndex: ['smb', 'dcerpc', 'interface', 'uuid'] },
    { title: 'Opnum', dataIndex: ['smb', 'dcerpc', 'opnum'] },
    { title: 'Status', dataIndex: ['smb', 'status'] },
    { title: 'Share', dataIndex: ['smb', 'share'] },
    { title: 'Filename', dataIndex: ['smb', 'filename'] },
    { title: 'Host', dataIndex: ['smb', 'ntlmssp', 'host'] },
    { title: 'User', dataIndex: ['smb', 'ntlmssp', 'user'] },
  ],
};

export default columns;
