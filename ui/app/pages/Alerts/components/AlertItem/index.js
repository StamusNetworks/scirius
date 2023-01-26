import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import { Badge, Col, Empty, Row, Spin, Tabs } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import axios from 'axios';
import ReactJson from 'react-json-view';

import * as config from 'config/Api';
import { dashboard } from 'config/Dashboard';
import { buildFilterParams } from 'ui/buildFilterParams';
import UICard from 'ui/components/UIElements/UICard';
import EventField from 'ui/components/EventField';
import ErrorHandler from 'ui/components/Error';
import SMBAlertCard from 'ui/components/SMBAlertCard';
import PCAPFile from 'ui/components/PCAPFile';

import { DlHorizontal, Container, Warning, Numbers, Pre } from './styles';
import AlertRelatedData from '../../../../components/AlertRelatedData';

// mapping between what comes from backend(here key) and what we want to show on the frontend(the value)
const protoMap = {
  Alert: 'Alert',
  Anomaly: 'Anomaly',
  Dcerpc: 'DCE/RPC',
  Dhcp: 'DHCP',
  Dnp3: 'DNP3',
  Dns: 'DNS',
  Enip: 'ENIP',
  Fileinfo: 'File Info',
  Flow: 'Flow',
  Ftp: 'FTP',
  Ftpdata: 'FTP data',
  Geneve: 'Geneve',
  Http: 'HTTP',
  Http2: 'HTTP2',
  Ikev2: 'IKEv2',
  Imap: 'IMAP',
  Krb5: 'KRB5',
  Modbus: 'Modbus',
  Mqtt: 'MQTT',
  Msn: 'MSN',
  Netflow: 'Netflow',
  Nfs: 'NFS',
  Ntp: 'NTP',
  Rdp: 'RDP',
  Rfb: 'RFB',
  Sip: 'SIP',
  Smb: 'SMB',
  Smtp: 'SMTP',
  Snmp: 'SNMP',
  Ssh: 'SSH',
  Stamus: 'Stamus',
  Tftp: 'TFTP',
  Tls: 'TLS',
  Vntag: 'VN-Tag',
  Vxlan: 'VXLAN',
};

export default class AlertItem extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      events: undefined,
      showTabs: false,
      collapsed: {},
      files: {},
      fileInfo: false,
      fileInfoLoading: false,
    };

    this.addFilter = this.addFilter.bind(this);
    this.fetchData = this.fetchData.bind(this);
    this.toggleCollapse = this.toggleCollapse.bind(this);
  }

  componentDidMount() {
    this.fetchData(this.props.data.flow_id);
  }

  formatString = (str, ...params) => {
    let result = str;
    for (let i = 0; i < params.length; i += 1) {
      const reg = new RegExp(`\\{${i}\\}`, 'gm');
      result = result.replace(reg, params[i]);
    }
    return result;
  };

  toggleCollapse(key) {
    const { collapsed } = this.state;

    if (key in collapsed) {
      collapsed[key] = !collapsed[key];
    } else {
      collapsed[key] = false;
    }

    this.setState({ collapsed });
  }

  addFilter(id, value, negated) {
    this.props.addFilter({ id, value, negated });
  }

  fetchData(flowId) {
    if (!this.state.showTabs) {
      // reset the files state for each event
      this.setState({ files: {}, fileInfo: false, fileInfoLoading: false });
      const filterParams = buildFilterParams(this.props.filterParams);
      const url = `${config.API_URL + config.ES_BASE_PATH}events_from_flow_id/?qfilter=flow_id:${flowId}&${filterParams}`;
      axios.get(url).then(res => {
        if (res.data !== null) {
          if ('Alert' in res.data) {
            for (let idx = 0; idx < Object.keys(res.data.Alert).length; idx += 1) {
              const item = res.data.Alert[idx];

              if (JSON.stringify(item) === JSON.stringify(this.props.data)) {
                res.data.Alert.splice(idx, 1);

                if (res.data.Alert.length === 0) {
                  delete res.data.Alert;
                }
                break;
              }
            }
          }

          // key needed in dataSource for antd table in each tab
          const events = {};
          Object.keys(res.data).forEach(key => {
            events[key] = res.data[key].map((obj, i) => ({ key: i, rawJson: obj }));
          });
          this.setState({ events });
        }
      });

      const fileUrl = `${config.API_URL}${config.ES_BASE_PATH}events_from_flow_id/?qfilter=flow_id:${flowId} AND fileinfo.stored:true&${filterParams}`;
      axios.get(fileUrl).then(res => {
        if (res.data !== null) {
          if ('Fileinfo' in res.data) {
            this.setState({ fileInfo: true, fileInfoLoading: true });
            res.data.Fileinfo.forEach(async ({ fileinfo, host }, i) => {
              if (this.state.files[fileinfo.sha256] !== undefined) {
                return;
              }
              this.setState({
                files: {
                  // eslint-disable-next-line react/no-access-state-in-setstate
                  ...this.state.files,
                  [fileinfo.sha256]: {
                    loading: true,
                    sha256: fileinfo.sha256,
                  },
                },
              });

              if (fileinfo.stored) {
                // verify the file exists
                const {
                  data: { status },
                } = await axios.get(`${config.API_URL + config.FILESTORE_PATH}${fileinfo.sha256}/status/?host=${host}`);
                if (status === 'available') {
                  this.setState({
                    files: {
                      // eslint-disable-next-line react/no-access-state-in-setstate
                      ...this.state.files,
                      [fileinfo.sha256]: {
                        file_id: fileinfo.file_id,
                        filename: fileinfo.filename,
                        size: fileinfo.size,
                        magic: fileinfo.magic,
                        sha256: fileinfo.sha256,
                        host,
                        downloading: false,
                        loading: false,
                      },
                    },
                  });
                  if (res.data.Fileinfo.length - 1 >= i) {
                    this.setState({ fileInfoLoading: false });
                  }
                }
              }
            });
          } else this.setState({ fileInfo: false, fileInfoLoading: false });
        }
      });
    }
    // eslint-disable-next-line react/no-access-state-in-setstate
    this.setState({ showTabs: !this.state.showTabs });
  }

  async downloadFile(file) {
    // show spinner
    // eslint-disable-next-line react/no-access-state-in-setstate
    this.setState({ files: { ...this.state.files, [file.sha256]: { ...this.state.files[file.sha256], downloading: true } } });

    // the request downloads the file from the host
    const {
      data: { retrieve },
    } = await axios.get(`${config.API_URL + config.FILESTORE_PATH}${file.sha256}/retrieve/?host=${file.host}`);

    if (retrieve === 'done') {
      // hide the spinner
      // eslint-disable-next-line react/no-access-state-in-setstate
      this.setState({ files: { ...this.state.files, [file.sha256]: { ...this.state.files[file.sha256], downloading: false } } });

      // trigger the download dialog
      const element = document.createElement('a');
      element.setAttribute('href', `${config.API_URL + config.FILESTORE_PATH}${file.sha256}/download/`);
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    }
  }

  renderFiles() {
    return (
      <Fragment>
        {Object.values(this.state.files).map(file => (
          <Container key={file.sha256}>
            <div>{file.sha256}</div>
            <div>{file.filename}</div>
            <div>{file.magic}</div>
            <div>{(file.size / 1000).toFixed(1)}KB</div>
            {!this.state.files[file.sha256].downloading ? (
              <a
                onClick={e => {
                  e.preventDefault();
                  this.downloadFile(file);
                }}
              >
                <DownloadOutlined />
              </a>
            ) : (
              <Spin size="small" />
            )}
          </Container>
        ))}
        <Warning>
          WARNING: These extracted files can contain malware or malicious payloads! DO NOT execute, run or activate those in non protected or non sand
          boxed environments. Stamus Networks is not responsible for any damage to your systems and infrastructure that might occur as a consequence
          of downloading them.
        </Warning>
      </Fragment>
    );
  }

  render() {
    const data = { ...this.props.data };
    const { events, showTabs } = this.state;
    let sourceNetwork;
    let targetNetwork;
    if (data.alert.source) {
      if (data.alert.source.net_info_agg) {
        sourceNetwork = (
          <ErrorHandler>
            <EventField
              field_name="Source Network"
              field="alert.source.net_info_agg"
              value={data.alert.source.net_info_agg}
              addFilter={this.addFilter}
            />
          </ErrorHandler>
        );
      } else if (data.alert.source.net_info) {
        sourceNetwork = (
          <React.Fragment>
            <dt>Source Network</dt>
            <dd>{data.alert.source.net_info.join(', ')}</dd>
          </React.Fragment>
        );
      }
    }
    if (data.alert.target) {
      if (data.alert.target.net_info_agg) {
        targetNetwork = (
          <ErrorHandler>
            <EventField
              field_name="Target Network"
              field="alert.target.net_info_agg"
              value={data.alert.target.net_info_agg}
              addFilter={this.addFilter}
            />
          </ErrorHandler>
        );
      } else if (data.alert.target.net_info) {
        targetNetwork = (
          <React.Fragment>
            <dt>Source Network</dt>
            <dd>{data.alert.target.net_info.join(', ')}</dd>
          </React.Fragment>
        );
      }
    }

    const hasTarget = data.alert.target !== undefined;
    const hasLateral = data.alert.lateral !== undefined;

    return (
      <Tabs style={{ width: 'calc(100vw - 280px)' }}>
        <Tabs.TabPane key="alert" tab="Synthetic view">
          {/* <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gridGap: '10px', paddingBottom: '10px' }}> */}
          <Row gutter={[10, 10]}>
            <Col md={24} lg={12} xl={8} xxl={6} flex>
              <UICard title="Signature" fullHeight>
                <DlHorizontal>
                  <ErrorHandler>
                    <EventField field_name="Signature" field="alert.signature" value={data.alert.signature} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="SID" field="alert.signature_id" value={data.alert.signature_id} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="Category" field="alert.category" value={data.alert.category} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField
                      field_name="Severity"
                      field="alert.severity"
                      value={data.alert.severity}
                      addFilter={this.addFilter}
                      format={(dashboard.basic.items.find(o => o.i === 'alert.severity') || {}).format}
                    />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="Revision" field="alert.rev" value={data.alert.rev} addFilter={this.addFilter} />
                  </ErrorHandler>
                  {data.alert.tag && (
                    <ErrorHandler>
                      <EventField field_name="Tagged" field="alert.tag" value={data.alert.tag} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                </DlHorizontal>
              </UICard>
            </Col>
            <Col md={24} lg={12} xl={8} xxl={6} flex>
              <UICard title="IP and basic information" fullHeight>
                <DlHorizontal>
                  {data.net_info && data.net_info.src_agg && (
                    <ErrorHandler>
                      <EventField field_name="Source Network" field="net_info.src_agg" value={data.net_info.src_agg} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  <ErrorHandler>
                    <EventField field_name="Source IP" field="src_ip" value={data.src_ip} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="Source port" field="src_port" value={data.src_port} addFilter={this.addFilter} />
                  </ErrorHandler>
                  {data.net_info && data.net_info.dest_agg && (
                    <ErrorHandler>
                      <EventField
                        field_name="Destination Network"
                        field="net_info.dest_agg"
                        value={data.net_info.dest_agg}
                        addFilter={this.addFilter}
                      />
                    </ErrorHandler>
                  )}
                  <ErrorHandler>
                    <EventField field_name="Destination IP" field="dest_ip" value={data.dest_ip} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="Destination port" field="dest_port" value={data.dest_port} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="IP protocol" field="proto" value={data.proto} addFilter={this.addFilter} />
                  </ErrorHandler>
                  {data.app_proto && (
                    <ErrorHandler>
                      <EventField field_name="Application protocol" field="app_proto" value={data.app_proto} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.app_proto_orig && (
                    <ErrorHandler>
                      <EventField
                        field_name="Original application protocol"
                        field="app_proto_orig"
                        value={data.app_proto_orig}
                        addFilter={this.addFilter}
                      />
                    </ErrorHandler>
                  )}
                  <ErrorHandler>
                    <EventField field_name="Probe" field="host" value={data.host} addFilter={this.addFilter} />
                  </ErrorHandler>
                  <ErrorHandler>
                    <EventField field_name="Network interface" field="in_iface" value={data.in_iface} addFilter={this.addFilter} />
                  </ErrorHandler>
                  {data.vlan && (
                    <ErrorHandler>
                      <EventField field_name="Vlan" field="vlan" value={data.vlan} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.tunnel && data.tunnel.src_ip && (
                    <ErrorHandler>
                      <EventField field_name="Tunnel Source IP" field="tunnel.src_ip" value={data.tunnel.src_ip} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.tunnel && data.tunnel.dest_ip && (
                    <ErrorHandler>
                      <EventField field_name="Tunnel Destination IP" field="tunnel.dest_ip" value={data.tunnel.dest_ip} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.tunnel && data.tunnel.proto && (
                    <ErrorHandler>
                      <EventField field_name="Tunnel Protocol" field="tunnel.proto" value={data.tunnel.proto} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.tunnel && data.tunnel.depth && (
                    <ErrorHandler>
                      <EventField field_name="Tunnel Depth" field="tunnel.depth" value={data.tunnel.depth} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                </DlHorizontal>
              </UICard>
            </Col>
            <Col md={24} lg={12} xl={8} xxl={6} flex>
              <UICard title="Enrichment" fullHeight>
                <DlHorizontal>
                  {!hasTarget && !hasLateral && (!data.fqdn || !data.fqdn.src) && (!data.fqdn || !data.fqdn.dest) && (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                  )}
                  {hasTarget && (
                    <React.Fragment>
                      {sourceNetwork}
                      <ErrorHandler>
                        <EventField field_name="Source IP" field="alert.source.ip" value={data.alert.source.ip} addFilter={this.addFilter} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField field_name="Source port" field="alert.source.port" value={data.alert.source.port} addFilter={this.addFilter} />
                      </ErrorHandler>
                      {targetNetwork}
                      <ErrorHandler>
                        <EventField field_name="Target IP" field="alert.target.ip" value={data.alert.target.ip} addFilter={this.addFilter} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField field_name="Target port" field="alert.target.port" value={data.alert.target.port} addFilter={this.addFilter} />
                      </ErrorHandler>
                    </React.Fragment>
                  )}
                  {hasLateral && (
                    <ErrorHandler>
                      <EventField field_name="Lateral movement" field="alert.lateral" value={data.alert.lateral} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.fqdn && data.fqdn.src && (
                    <ErrorHandler>
                      <EventField field_name="FQDN Source" field="fqdn.src" value={data.fqdn.src} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                  {data.fqdn && data.fqdn.dest && (
                    <ErrorHandler>
                      <EventField field_name="FQDN Destination" field="fqdn.dest" value={data.fqdn.dest} addFilter={this.addFilter} />
                    </ErrorHandler>
                  )}
                </DlHorizontal>
              </UICard>
            </Col>
            {data.dns && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="DNS" fullHeight>
                  {data.dns.query.map(query => (
                    <>
                      {query.rrname && (
                        <ErrorHandler>
                          <EventField field_name="Queried Name" field="dns.query.rrname" value={query.rrname} addFilter={this.addFilter} />
                        </ErrorHandler>
                      )}
                      {query.rrtype && (
                        <ErrorHandler>
                          <EventField field_name="Queried Type" field="dns.query.rrtype" value={query.rrtype} addFilter={this.addFilter} />
                        </ErrorHandler>
                      )}
                    </>
                  ))}
                </UICard>
              </Col>
            )}
            {data.geoip && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="Geo IP" fullHeight>
                  <DlHorizontal>
                    {data.geoip.country_name && (
                      <ErrorHandler>
                        <EventField field_name="Country" field="geoip.country_name" value={data.geoip.country_name} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.geoip.city_name && (
                      <ErrorHandler>
                        <EventField
                          field_name="Country Code"
                          field="geoip.country_code2"
                          value={data.geoip.country_code2}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                    {data.geoip.provider && data.geoip.provider.autonomous_system_number && (
                      <ErrorHandler>
                        <EventField
                          field_name="AS Number"
                          field="geoip.provider.autonomous_system_number"
                          value={data.geoip.provider.autonomous_system_number}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                    {data.geoip.provider && data.geoip.provider.autonomous_system_organization && (
                      <ErrorHandler>
                        <EventField
                          field_name="AS Organization"
                          field="geoip.provider.autonomous_system_organization"
                          value={data.geoip.provider.autonomous_system_organization}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}

            {data.http !== undefined && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="HTTP" fullHeight>
                  <DlHorizontal>
                    <ErrorHandler>
                      <EventField field_name="Host" field="http.hostname" value={data.http.hostname} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="URL" field="http.url" value={data.http.url} addFilter={this.addFilter} />
                    </ErrorHandler>
                    {data.http.status !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Status" field="http.status" value={data.http.status} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    <ErrorHandler>
                      <EventField field_name="Method" field="http.http_method" value={data.http.http_method} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="User Agent" field="http.http_user_agent" value={data.http.http_user_agent} addFilter={this.addFilter} />
                    </ErrorHandler>
                    {data.http.http_refer !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Referrer" field="http.http_refer" value={data.http.http_refer} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.http.http_port !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Port" field="http.http_port" value={data.http.http_port} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.http.http_content_type !== undefined && (
                      <ErrorHandler>
                        <EventField
                          field_name="Content Type"
                          field="http.http_content_type"
                          value={data.http.http_content_type}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                    {data.http.length !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Length" field="http.length" value={data.http.length} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.http.server !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Server" field="http.server" value={data.http.server} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.http.accept_language !== undefined && (
                      <ErrorHandler>
                        <EventField
                          field_name="Accept Language"
                          field="http.accept_language"
                          value={data.http.accept_language}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                    {data.http.protocol !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Protocol" field="http.protocol" value={data.http.protocol} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            {data.tls !== undefined && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="TLS" fullHeight>
                  <DlHorizontal>
                    <ErrorHandler>
                      <EventField field_name="Subject" field="tls.subject" value={data.tls.subject} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="Issuer" field="tls.issuerdn" value={data.tls.issuerdn} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="Server Name Indication" field="tls.sni" value={data.tls.sni} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="Not Before" field="tls.notbefore" value={data.tls.notbefore} addFilter={this.addFilter} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField field_name="Not After" field="tls.notafter" value={data.tls.notafter} addFilter={this.addFilter} />
                    </ErrorHandler>
                    {data.tls.ja3 && data.tls.ja3.hash !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="JA3" field="tls.ja3.hash" value={data.tls.ja3.hash} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.tls.ja3 &&
                      data.tls.ja3.agent !== undefined &&
                      data.tls.ja3.agent.map(agent => (
                        <ErrorHandler key={Math.random()}>
                          {/* eslint-disable-next-line react/no-array-index-key */}
                          <EventField field_name="User-Agent" field="tls.ja3.agent" value={agent} addFilter={this.addFilter} key={`to-${agent}`} />
                        </ErrorHandler>
                      ))}
                    {data.tls.ja3s && data.tls.ja3s.hash !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="JA3S" field="tls.ja3s.hash" value={data.tls.ja3s.hash} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.tls.version !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Version" field="tls.version" value={data.tls.version} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.tls.cipher_suite !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Cipher Suite" field="tls.cipher_suite" value={data.tls.cipher_suite} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.tls.cipher_security !== undefined && (
                      <ErrorHandler>
                        <EventField
                          field_name="Cipher Security"
                          field="tls.cipher_security"
                          value={data.tls.cipher_security}
                          addFilter={this.addFilter}
                        />
                      </ErrorHandler>
                    )}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            {data.smtp !== undefined && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="SMTP" fullHeight>
                  <DlHorizontal>
                    {data.smtp.mail_from !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="From" field="smtp.mail_from" value={data.smtp.mail_from} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                    {data.smtp.rcpt_to !== undefined &&
                      data.smtp.rcpt_to.map((mail, idx) => (
                        <ErrorHandler key={Math.random()}>
                          {/* eslint-disable-next-line react/no-array-index-key */}
                          <EventField field_name="To" field="smtp.rcpt_to" value={mail} addFilter={this.addFilter} key={`to-${idx}`} />
                        </ErrorHandler>
                      ))}
                    {data.smtp.helo !== undefined && (
                      <ErrorHandler>
                        <EventField field_name="Helo" field="smtp.helo" value={data.smtp.helo} addFilter={this.addFilter} />
                      </ErrorHandler>
                    )}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            {data.ssh !== undefined && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="SSH" fullHeight>
                  <DlHorizontal>
                    {data.ssh.client && (
                      <React.Fragment>
                        <ErrorHandler>
                          <EventField
                            field_name="Client Software"
                            field="ssh.client.software_version"
                            value={data.ssh.client.software_version}
                            addFilter={this.addFilter}
                          />
                        </ErrorHandler>
                        <ErrorHandler>
                          <EventField
                            field_name="Client Version"
                            field="ssh.client.proto_version"
                            value={data.ssh.client.proto_version}
                            addFilter={this.addFilter}
                          />
                        </ErrorHandler>
                      </React.Fragment>
                    )}
                    {data.ssh.server && (
                      <React.Fragment>
                        <ErrorHandler>
                          <EventField
                            field_name="Server Software"
                            field="ssh.server.software_version"
                            value={data.ssh.server.software_version}
                            addFilter={this.addFilter}
                          />
                        </ErrorHandler>
                        <ErrorHandler>
                          <EventField
                            field_name="Server Version"
                            field="ssh.server.proto_version"
                            value={data.ssh.server.proto_version}
                            addFilter={this.addFilter}
                          />
                        </ErrorHandler>
                      </React.Fragment>
                    )}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            {data.ether !== undefined && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="Ethernet" fullHeight>
                  <DlHorizontal>
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField field_name="Source MAC" field="ether.src_mac" value={data.ether.src_mac} addFilter={this.addFilter} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField field_name="Destination MAC" field="ether.dest_mac" value={data.ether.dest_mac} addFilter={this.addFilter} />
                      </ErrorHandler>
                    </React.Fragment>
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            {data.alert.metadata && (
              <Col md={24} lg={12} xl={8} xxl={6} flex>
                <UICard title="Signature metadata" fullHeight>
                  <DlHorizontal>
                    {Object.entries(data.alert.metadata).map(field => {
                      const value = field[1] === null ? '' : field[1].join(', ');
                      const key = field[0] === null ? '' : field[0];
                      return (
                        <ErrorHandler key={key}>
                          <EventField field_name={key} field={`alert.metadata.${key}`} value={value} addFilter={this.addFilter} />
                        </ErrorHandler>
                      );
                    })}
                  </DlHorizontal>
                </UICard>
              </Col>
            )}
            <Col md={24} lg={12} xl={8} xxl={6} flex>
              <SMBAlertCard data={data} addFilter={this.addFilter} />
            </Col>
            {/* </div> */}
            {data.payload_printable && (
              <Col md={24} flex>
                <UICard title="Payload printable" noPadding>
                  <Pre>{data.payload_printable}</Pre>
                </UICard>
              </Col>
            )}
            {data.http && data.http.http_request_body_printable && (
              <Col md={24} flex>
                <UICard title="HTTP request body" noPadding>
                  <Pre>{data.http.http_request_body_printable}</Pre>
                </UICard>
              </Col>
            )}
            {data.http && data.http.http_response_body_printable && (
              <Col md={24} flex>
                <UICard title="HTTP response body" noPadding>
                  <Pre>{data.http.http_response_body_printable}</Pre>
                </UICard>
              </Col>
            )}
          </Row>
        </Tabs.TabPane>
        {showTabs && events && (
          <React.Fragment key="json-related">
            {Object.keys(events)
              .sort()
              .map(key => (
                <Tabs.TabPane
                  key={`events-${key}`}
                  tab={
                    <Numbers>
                      <span>{`Related ${protoMap[key]}${key === 'Alert' && Object.keys(events[key]).length > 1 ? 's' : ''}`}</span>
                      <Badge
                        count={Object.keys(events[key]).length || <span className="ant-badge-count">0</span>}
                        overflowCount={99999}
                        style={{ background: '#5b595c' }}
                      />
                    </Numbers>
                  }
                >
                  <AlertRelatedData type={key} data={events[key]} />
                </Tabs.TabPane>
              ))}
          </React.Fragment>
        )}
        {showTabs && (
          <Tabs.TabPane key="json-alert" tab="JSON View">
            <ReactJson
              name={false}
              src={data}
              displayDataTypes={false}
              displayObjectSize={false}
              collapseStringsAfterLength={150}
              collapsed={false}
            />
          </Tabs.TabPane>
        )}
        {showTabs && JSON.stringify(this.state.files) !== '{}' && (
          <Tabs.TabPane
            key="json-files"
            tab={
              <Numbers>
                <span>Files</span>
                <Badge
                  count={Object.values(this.state.files).length || <span className="ant-badge-count">0</span>}
                  overflowCount={99999}
                  style={{ background: '#5b595c' }}
                />
              </Numbers>
            }
          >
            {this.state.fileInfo && this.state.fileInfoLoading && (
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100px' }}>
                <Spin size="small" />
              </div>
            )}
            {!this.state.fileInfo && !this.state.fileInfoLoading && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
            {this.state.fileInfo && !this.state.fileInfoLoading && this.renderFiles()}
          </Tabs.TabPane>
        )}
        {showTabs && (
          <Tabs.TabPane key="json-pcap" tab="PCAP File">
            <PCAPFile alertData={this.props.data} />
          </Tabs.TabPane>
        )}
        {!events && <Tabs.TabPane key="events" tab={<Spin size="small" />} />}
      </Tabs>
    );
  }
}
AlertItem.propTypes = {
  data: PropTypes.any,
  addFilter: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
};
