import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import ReactJson from 'react-json-view';
import _ from 'lodash';
import { Badge, Dropdown, Empty, Spin, Table, Tabs } from 'antd';
import { DownloadOutlined, LinkOutlined } from '@ant-design/icons';

import * as config from 'config/Api';
import UICard from 'ui/components/UIElements/UICard';
import EventField from 'ui/components/EventField';
import ErrorHandler from 'ui/components/Error';
import SMBAlertCard from 'ui/components/SMBAlertCard';
import PCAPFile from 'ui/components/PCAPFile';
import { KillChainStepsEnum } from 'ui/maps/KillChainStepsEnum';
import { withStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';
import AlertRelatedData from 'ui/components/AlertRelatedData';
import { DlHorizontal, Warning, Numbers, Pre, TabPaneResponsive } from './styles';

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

class AlertItem extends React.Component {
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

  fetchData(flowId) {
    if (!this.state.showTabs) {
      // reset the files state for each event
      this.setState({ files: {}, fileInfo: false, fileInfoLoading: false });
      const url = `${config.API_URL + config.ES_BASE_PATH}events_from_flow_id/?qfilter=flow_id:${flowId}&${this.props.filterParams}`;
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

      const fileUrl = `${config.API_URL}${config.ES_BASE_PATH}events_from_flow_id/?qfilter=flow_id:${flowId} AND fileinfo.stored:true&${this.props.filterParams}`;
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
                        mimetype: fileinfo.mimetype,
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
    let dataSource = [];
    Object.values(this.state.files).forEach((file, i) => {
      dataSource = [
        ...dataSource,
        {
          key: i,
          sha256: file.sha256,
          filename: file.filename,
          mimetype: file.mimetype,
          size: file.size,
          download: file,
        },
      ];
    });

    const columns = [
      {
        title: 'Sha256',
        dataIndex: 'sha256',
        key: 'sha256',
        width: 488,
        render: val => (
          <Dropdown
            menu={{
              items: [
                {
                  key: 'virustotal',
                  label: (
                    <a href={`https://www.virustotal.com/gui/file/${encodeURIComponent(val)}`} target="_blank">
                      <LinkOutlined /> Open link to VirusTotal
                    </a>
                  ),
                },
              ],
            }}
            trigger={['click']}
            destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
            onClick={e => e.stopPropagation()}
          >
            <a>{val}</a>
          </Dropdown>
        ),
      },
      {
        title: 'Filename',
        dataIndex: 'filename',
        key: 'filename',
      },
      {
        title: 'Mimetype',
        dataIndex: 'mimetype',
        key: 'mimetype',
      },
      {
        title: 'Size',
        dataIndex: 'size',
        key: 'size',
      },
      {
        title: 'Download',
        dataIndex: 'download',
        key: 'download',
        render: file =>
          !this.state.files[file.sha256].downloading ? (
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
          ),
      },
    ];
    return (
      <Fragment>
        <Table columns={columns} dataSource={dataSource} />
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
            <EventField filter={new Filter('alert.source.net_info_agg', data.alert.source.net_info_agg)} />
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
            <EventField filter={new Filter('alert.target.net_info_agg', data.alert.target.net_info_agg)} />
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
          <TabPaneResponsive>
            {/* Signature should always be displayed */}
            <UICard data-test="alert-card-Signature" title="Signature" fullHeight>
              <DlHorizontal>
                <ErrorHandler>
                  <EventField filter={new Filter('alert.signature', data.alert.signature)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('alert.signature_id', data.alert.signature_id)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('alert.category', data.alert.category)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('alert.severity', data.alert.severity)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('alert.rev', data.alert.rev)} />
                </ErrorHandler>
                {data.alert.tag && (
                  <ErrorHandler>
                    <EventField filter={new Filter('alert.tag', data.alert.tag)} />
                  </ErrorHandler>
                )}
              </DlHorizontal>
            </UICard>

            {/* IP and basic information should always be displayed */}
            <UICard data-test="alert-card-IP and basic information" title="IP and basic information" fullHeight>
              <DlHorizontal>
                {data.net_info && data.net_info.src_agg && (
                  <ErrorHandler>
                    <EventField filter={new Filter('net_info.src_agg', data.net_info.src_agg)} />
                  </ErrorHandler>
                )}
                <ErrorHandler>
                  {/* filter{new Filter(src_ip,data.src_ip} />) */}
                  <EventField filter={new Filter('src_ip', data.src_ip)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('src_port', data.src_port)} />
                </ErrorHandler>
                {data.net_info && data.net_info.dest_agg && (
                  <ErrorHandler>
                    <EventField filter={new Filter('net_info.dest_agg', data.net_info.dest_agg)} />
                  </ErrorHandler>
                )}
                <ErrorHandler>
                  <EventField filter={new Filter('dest_ip', data.dest_ip)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('dest_port', data.dest_port)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('proto', data.proto)} />
                </ErrorHandler>
                {data.app_proto && (
                  <ErrorHandler>
                    <EventField filter={new Filter('app_proto', data.app_proto)} />
                  </ErrorHandler>
                )}
                {data.app_proto_orig && (
                  <ErrorHandler>
                    <EventField filter={new Filter('app_proto_orig', data.app_proto_orig)} />
                  </ErrorHandler>
                )}
                <ErrorHandler>
                  <EventField filter={new Filter('host', data.host)} />
                </ErrorHandler>
                <ErrorHandler>
                  <EventField filter={new Filter('in_iface', data.in_iface)} />
                </ErrorHandler>
                {data.vlan && (
                  <ErrorHandler>
                    <EventField filter={new Filter('vlan', data.vlan)} />
                  </ErrorHandler>
                )}
                {data.tunnel && data.tunnel.src_ip && (
                  <ErrorHandler>
                    <EventField filter={new Filter('tunnel.src_ip', data.tunnel.src_ip)} />
                  </ErrorHandler>
                )}
                {data.tunnel && data.tunnel.dest_ip && (
                  <ErrorHandler>
                    <EventField filter={new Filter('tunnel.dest_ip', data.tunnel.dest_ip)} />
                  </ErrorHandler>
                )}
                {data.tunnel && data.tunnel.proto && (
                  <ErrorHandler>
                    <EventField filter={new Filter('tunnel.proto', data.tunnel.proto)} />
                  </ErrorHandler>
                )}
                {data.tunnel && data.tunnel.depth && (
                  <ErrorHandler>
                    <EventField filter={new Filter('tunnel.depth', data.tunnel.depth)} />
                  </ErrorHandler>
                )}
              </DlHorizontal>
            </UICard>

            {/* Enrichment should always be displayed */}
            <UICard data-test="alert-card-Enrichment" title="Enrichment" fullHeight>
              <DlHorizontal>
                {!hasTarget && !hasLateral && (!data.fqdn || !data.fqdn.src) && (!data.fqdn || !data.fqdn.dest) && (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                )}
                {hasTarget && (
                  <React.Fragment>
                    {sourceNetwork}
                    <ErrorHandler>
                      <EventField filter={new Filter('alert.source.ip', data.alert.source.ip)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('alert.source.port', data.alert.source.port)} />
                    </ErrorHandler>
                    {targetNetwork}
                    <ErrorHandler>
                      <EventField filter={new Filter('alert.target.ip', data.alert.target.ip)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('alert.target.port', data.alert.target.port)} />
                    </ErrorHandler>
                  </React.Fragment>
                )}
                {hasLateral && (
                  <ErrorHandler>
                    <EventField filter={new Filter('alert.lateral', data.alert.lateral)} />
                  </ErrorHandler>
                )}
                {data.fqdn && data.fqdn.src && (
                  <ErrorHandler>
                    <EventField filter={new Filter('fqdn.src', data.fqdn.src)} />
                  </ErrorHandler>
                )}
                {data.fqdn && data.fqdn.dest && (
                  <ErrorHandler>
                    <EventField filter={new Filter('fqdn.dest', data.fqdn.dest)} />
                  </ErrorHandler>
                )}
              </DlHorizontal>
            </UICard>

            {data.app_proto === 'dns' && (
              <UICard data-test="alert-card-DNS" title="DNS" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.dns) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.dns?.query.map(query => (
                    <>
                      {query.rrname && (
                        <ErrorHandler>
                          <EventField filter={new Filter('dns.query.rrname', query.rrname)} />
                        </ErrorHandler>
                      )}
                      {query.rrtype && (
                        <ErrorHandler>
                          <EventField filter={new Filter('dns.query.rrtype', query.rrtype)} />
                        </ErrorHandler>
                      )}
                    </>
                  ))}
                </DlHorizontal>
              </UICard>
            )}

            {/* Flow should always be displayed */}
            <UICard data-test="alert-card-Flow" title="Flow" fullHeight>
              <DlHorizontal>
                {_.isEmpty(data.flow) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                {data.flow && (
                  <React.Fragment>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.start', data.flow?.start)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.src_ip', data.flow?.src_ip)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.dest_ip', data.flow?.dest_ip)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.bytes_toserver', data.flow.bytes_toserver)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.bytes_toclient', data.flow.bytes_toclient)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.pkts_toserver', data.flow.pkts_toserver)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow.pkts_toclient', data.flow.pkts_toclient)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('flow_id', data.flow_id)} />
                    </ErrorHandler>
                  </React.Fragment>
                )}
              </DlHorizontal>
            </UICard>

            {/* Geo IP should always be displayed */}
            <UICard data-test="alert-card-Geo IP" title="Geo IP" fullHeight>
              <DlHorizontal>
                {_.isEmpty(data.geoip) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                {data.geoip?.country_name && (
                  <ErrorHandler>
                    <EventField filter={new Filter('geoip.country_name', data.geoip.country_name)} />
                  </ErrorHandler>
                )}
                {data.geoip?.country && (
                  <ErrorHandler>
                    <EventField filter={new Filter('geoip.country.iso_code', data.geoip.country.iso_code)} />
                  </ErrorHandler>
                )}
                {data.geoip?.provider && data.geoip?.provider.autonomous_system_number && (
                  <ErrorHandler>
                    <EventField filter={new Filter('geoip.provider.autonomous_system_number', data.geoip.provider.autonomous_system_number)} />
                  </ErrorHandler>
                )}
                {data.geoip?.provider && data.geoip?.provider.autonomous_system_organization && (
                  <ErrorHandler>
                    <EventField
                      filter={new Filter('geoip.provider.autonomous_system_organization', data.geoip.provider.autonomous_system_organization)}
                    />
                  </ErrorHandler>
                )}
              </DlHorizontal>
            </UICard>

            {data.app_proto === 'http' && (
              <UICard data-test="alert-card-HTTP" title="HTTP" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.http) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.http && (
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField filter={new Filter('http.hostname', data.http.hostname)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('http.url', data.http.url)} />
                      </ErrorHandler>
                      {data.http.status !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.status', data.http.status)} />
                        </ErrorHandler>
                      )}
                      <ErrorHandler>
                        <EventField filter={new Filter('http.http_method', data.http.http_method)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('http.http_user_agent', data.http.http_user_agent)} />
                      </ErrorHandler>
                      {data.http.http_refer !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.http_refer', data.http.http_refer)} />
                        </ErrorHandler>
                      )}
                      {data.http.http_port !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.http_port', data.http.http_port)} />
                        </ErrorHandler>
                      )}
                      {data.http.http_content_type !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.http_content_type', data.http.http_content_type)} />
                        </ErrorHandler>
                      )}
                      {data.http.length !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.length', data.http.length)} />
                        </ErrorHandler>
                      )}
                      {data.http.server !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.server', data.http.server)} />
                        </ErrorHandler>
                      )}
                      {data.http.accept_language !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.accept_language', data.http.accept_language)} />
                        </ErrorHandler>
                      )}
                      {data.http.protocol !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('http.protocol', data.http.protocol)} />
                        </ErrorHandler>
                      )}
                    </React.Fragment>
                  )}
                </DlHorizontal>
              </UICard>
            )}

            {data.app_proto === 'tls' && (
              <UICard data-test="alert-card-TLS" title="TLS" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.tls) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.tls && (
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField filter={new Filter('tls.subject', data.tls.subject)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('tls.issuerdn', data.tls.issuerdn)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('tls.sni', data.tls.sni)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('tls.notbefore', data.tls.notbefore)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('tls.notafter', data.tls.notafter)} />
                      </ErrorHandler>
                      {data.tls.ja3 && data.tls.ja3.hash !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('tls.ja3.hash', data.tls.ja3.hash)} />
                        </ErrorHandler>
                      )}
                      {data.tls.ja3 &&
                        data.tls.ja3.agent !== undefined &&
                        data.tls.ja3.agent.map(agent => (
                          <ErrorHandler key={Math.random()}>
                            {/* eslint-disable-next-line react/no-array-index-key */}
                            <EventField filter={new Filter('tls.ja3.agent', agent)} key={`to-${agent}`} />
                          </ErrorHandler>
                        ))}
                      {data.tls.ja3s && data.tls.ja3s.hash !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('tls.ja3s.hash', data.tls.ja3s.hash)} />
                        </ErrorHandler>
                      )}
                      {data.tls.version !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('tls.version', data.tls.version)} />
                        </ErrorHandler>
                      )}
                      {data.tls.cipher_suite !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('tls.cipher_suite', data.tls.cipher_suite)} />
                        </ErrorHandler>
                      )}
                      {data.tls.cipher_security !== undefined && (
                        <ErrorHandler>
                          <EventField filter={new Filter('tls.cipher_security', data.tls.cipher_security)} />
                        </ErrorHandler>
                      )}
                    </React.Fragment>
                  )}
                </DlHorizontal>
              </UICard>
            )}

            {data.app_proto === 'smtp' && (
              <UICard data-test="alert-card-SMTP" title="SMTP" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.smtp) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.smtp?.mail_from !== undefined && (
                    <ErrorHandler>
                      <EventField filter={new Filter('smtp.mail_from', data.smtp.mail_from)} />
                    </ErrorHandler>
                  )}
                  {data.smtp?.rcpt_to !== undefined &&
                    data.smtp?.rcpt_to.map((mail, idx) => (
                      <ErrorHandler key={Math.random()}>
                        {/* eslint-disable-next-line react/no-array-index-key */}
                        <EventField filter={new Filter('smtp.rcpt_to', mail)} key={`to-${idx}`} />
                      </ErrorHandler>
                    ))}
                  {data.smtp?.helo !== undefined && (
                    <ErrorHandler>
                      <EventField filter={new Filter('smtp.helo', data.smtp.helo)} />
                    </ErrorHandler>
                  )}
                </DlHorizontal>
              </UICard>
            )}

            {data.app_proto === 'ssh' && (
              <UICard data-test="alert-card-SSH" title="SSH" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.ssh) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.ssh?.client && (
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField filter={new Filter('ssh.client.software_version', data.ssh.client.software_version)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('ssh.client.proto_version', data.ssh.client.proto_version)} />
                      </ErrorHandler>
                    </React.Fragment>
                  )}
                  {data.ssh?.server && (
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField filter={new Filter('ssh.server.software_version', data.ssh.server.software_version)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('ssh.server.proto_version', data.ssh.server.proto_version)} />
                      </ErrorHandler>
                    </React.Fragment>
                  )}
                </DlHorizontal>
              </UICard>
            )}

            {/* Ethernet should always be displayed */}
            <UICard data-test="alert-card-Ethernet" title="Ethernet" fullHeight>
              <DlHorizontal>
                {_.isEmpty(data.ether) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                {data.ether && (
                  <React.Fragment>
                    <ErrorHandler>
                      <EventField filter={new Filter('ether.src_mac', data.ether.src_mac)} />
                    </ErrorHandler>
                    <ErrorHandler>
                      <EventField filter={new Filter('ether.dest_mac', data.ether.dest_mac)} />
                    </ErrorHandler>
                  </React.Fragment>
                )}
              </DlHorizontal>
            </UICard>

            {/* Signature metadata should always be displayed */}
            {data.event_type !== 'stamus' && data.event_type === 'alert' && (
              <UICard data-test="alert-card-Signature metadata" title="Signature metadata" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.alert.metadata) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.alert.metadata &&
                    Object.entries(data.alert.metadata).map(field => {
                      const value = field[1] === null ? '' : field[1].join(', ');
                      const key = field[0] === null ? '' : field[0];
                      const fieldName = key.length > 0 ? key[0].toUpperCase() + key.slice(1).replace('_', ' ') : '';
                      return (
                        <ErrorHandler key={key}>
                          <EventField filter={new Filter(`alert.metadata.${key}`, value, { title: fieldName })} />
                        </ErrorHandler>
                      );
                    })}
                </DlHorizontal>
              </UICard>
            )}

            {data.event_type === 'stamus' && data.event_type !== 'alert' && (
              <UICard title="Stamus Method" fullHeight>
                <DlHorizontal>
                  {_.isEmpty(data.stamus) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
                  {data.stamus && (
                    <React.Fragment>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.asset', data.stamus.asset)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.source', data.stamus.source)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.threat_name', data.stamus.threat_name)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.family_name', data.stamus.family_name)} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.kill_chain', KillChainStepsEnum[data.stamus.kill_chain])} />
                      </ErrorHandler>
                      <ErrorHandler>
                        <EventField filter={new Filter('stamus.threat_id', data.stamus.threat_id)} />
                      </ErrorHandler>
                    </React.Fragment>
                  )}
                </DlHorizontal>
              </UICard>
            )}

            {data.app_proto === 'smb' && <SMBAlertCard data={data} />}
          </TabPaneResponsive>
          {data.payload_printable && (
            <UICard data-test="alert-card-Payload printable" title="Payload printable" noPadding style={{ marginBottom: '10px' }}>
              {_.isEmpty(data.payload_printable) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              {data.payload_printable && <Pre>{data.payload_printable}</Pre>}
            </UICard>
          )}
          {data.http?.http_request_body_printable && (
            <UICard data-test="alert-card-HTTP request body" title="HTTP request body" noPadding style={{ marginBottom: '10px' }}>
              {_.isEmpty(data.http.http_request_body_printable) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              {data.http?.http_request_body_printable && <Pre>{data.http.http_request_body_printable}</Pre>}
            </UICard>
          )}
          {data.http?.http_response_body_printable && (
            <UICard data-test="alert-card-HTTP response body" title="HTTP response body" noPadding>
              {_.isEmpty(data.http.http_response_body_printable) && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              {data.http?.http_response_body_printable && <Pre>{data.http.http_response_body_printable}</Pre>}
            </UICard>
          )}
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
        {showTabs && !_.isEmpty(this.props.data.capture_file) && (
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
  filterParams: PropTypes.string.isRequired,
};

export default withStore(AlertItem);
