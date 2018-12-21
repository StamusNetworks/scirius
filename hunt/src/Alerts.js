/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/


import React from 'react';
import PropTypes from 'prop-types';
import ReactJson from 'react-json-view';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import axios from 'axios';
import moment from 'moment';
import store from 'store';
import md5 from 'md5';
import { HuntList } from './Api';
import { buildQFilter } from './helpers/buildQFilter';
import RuleToggleModal from './RuleToggleModal';
import { HuntFilter } from './Filter';
import EventField from './EventField';
import * as config from './config/Api';


export class AlertsList extends HuntList {
    constructor(props) {
        super(props);

        const huntFilters = store.get('huntFilters');
        const rulesFilters = (typeof huntFilters !== 'undefined' && typeof huntFilters.alertslist !== 'undefined') ? huntFilters.alertslist.data : [];
        this.state = {
            alerts: [],
            rulesets: [],
            loading: true,
            refresh_data: false,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rulesFilters,
            supported_actions: []
        };
        this.fetchData = this.fetchData.bind(this);
    }

    componentDidMount() {
        this.fetchData(this.props.config, this.props.filters);
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
                this.setState({ rulesets: res.data.results });
            });
        }
        const huntFilters = store.get('huntFilters');
        axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
            (res) => {
                const fdata = [];
                const keys = Object.keys(res.data);
                const values = Object.values(res.data);
                for (let i = 0; i < keys.length; i += 1) {
                    /* Only ES filter are allowed for Alert page */
                    if (['filter'].indexOf(values[i].queryType) !== -1) {
                        if (values[i].filterType !== 'hunt') {
                            fdata.push(values[i]);
                        }
                    }
                }
                const currentCheckSum = md5(JSON.stringify(fdata));
                if ((typeof huntFilters === 'undefined' || typeof huntFilters.alertslist === 'undefined') || huntFilters.alertslist.checkSum !== currentCheckSum) {
                    store.set('huntFilters', {
                        ...huntFilters,
                        alertslist: {
                            checkSum: currentCheckSum,
                            data: fdata
                        }
                    });
                    this.setState({ rulesFilters: fdata });
                }
            }
        );
        this.loadActions();
    }

    fetchData(state, filters) {
        let stringFilters = buildQFilter(filters, this.props.systemSettings);
        if (stringFilters === null) {
            stringFilters = '';
        } else {
            stringFilters = `&filter=${stringFilters}`;
        }
        this.setState({ refresh_data: true, loading: true });
        const url = `${config.API_URL + config.ES_BASE_PATH}alerts_tail&search_target=0&${this.buildListUrlParams(state)}&from_date=${this.props.from_date}${stringFilters}`;
        axios.get(url).then((res) => {
            if ((res.data !== null) && (typeof res.data !== 'string')) {
                this.setState({ alerts: res.data, loading: false });
            } else {
                this.setState({ loading: false });
            }
        });
    }

    render() {
        return (
            <div className="AlertsList HuntList">
                <HuntFilter
                    ActiveFilters={this.props.filters}
                    config={this.props.config}
                    ActiveSort={this.props.config.sort}
                    UpdateFilter={this.UpdateFilter}
                    UpdateSort={this.UpdateSort}
                    setViewType={this.setViewType}
                    filterFields={this.state.rulesFilters}
                    sort_config={undefined}
                    displayToggle={this.state.display_toggle}
                    actionsButtons={this.actionsButtons}
                    queryType={['filter']}
                />
                <Spinner loading={this.state.loading}>
                </Spinner>
                <ListView>
                    {this.state.alerts.map((rule) => (
                        // eslint-disable-next-line no-underscore-dangle
                        <AlertInList key={rule._id} id={rule._id} data={rule._source} from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} filters={this.props.filters} addFilter={this.addFilter} />
                    ))}
                </ListView>
                <RuleToggleModal
                    show={this.state.action.view}
                    action={this.state.action.type}
                    config={this.props.config}
                    filters={this.props.filters}
                    close={this.closeAction}
                    rulesets={this.state.rulesets}
                />
            </div>
        );
    }
}

class AlertInList extends React.Component {
    constructor(props) {
        super(props);
        this.addFilter = this.addFilter.bind(this);
    }

    addFilter(key, value, negated) {
        this.props.addFilter(key, value, negated);
    }

    render() {
        const data = { ...this.props.data };
        const ipParams = (<div> {data.src_ip} <span className="glyphicon glyphicon-arrow-right"></span> {data.dest_ip}</div>);
        let sourceNetwork;
        let targetNetwork;
        if (data.alert.source) {
            if (data.alert.source.net_info_agg) {
                sourceNetwork = (<EventField field_name="Source Network" field="alert.source.net_info_agg" value={data.alert.source.net_info_agg} addFilter={this.addFilter} />);
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
                    <EventField
                        field_name="Target Network"
                        field="alert.target.net_info_agg"
                        value={data.alert.target.net_info_agg}
                        addFilter={this.addFilter}
                    />
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
        const hasLateralOrTarget = hasTarget || hasLateral;

        const addInfo = [
            <ListViewInfoItem key="timestamp"><p>{moment(data.timestamp).format('YYYY-MM-DD, hh:mm:ss a')}</p>
            </ListViewInfoItem>,
            <ListViewInfoItem key="app_proto"><p>Proto: {data.app_proto}</p></ListViewInfoItem>,
            <ListViewInfoItem key="host"><p>Probe: {data.host}</p></ListViewInfoItem>,
            <ListViewInfoItem key="category"><p>Category: {data.alert.category}</p></ListViewInfoItem>,
        ];
        let iconclass = 'primary';
        if (data.alert.tag) {
            addInfo.push(<ListViewInfoItem key="tag"><p>Tag: {data.alert.tag}</p></ListViewInfoItem>);
            iconclass = data.alert.tag;
        }

        let dnsQuery;
        if (data.dns && data.dns.query) {
            [dnsQuery] = data.dns.query;
        }

        return (
            <ListViewItem
                id={this.props.id}
                leftContent={<ListViewIcon type="pf" name="security" className={iconclass} />}
                description={<span data-toggle="tooltip" title={data.alert.signature}>{data.alert.signature}</span>}
                heading={ipParams}
                additionalInfo={addInfo}
            >
                <Row>
                    <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5 className="card-title">Signature</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    <EventField field_name="Signature" field="alert.signature" value={data.alert.signature} addFilter={this.addFilter} />
                                    <EventField field_name="SID" field="alert.signature_id" value={data.alert.signature_id} addFilter={this.addFilter} />
                                    <EventField field_name="Category" field="alert.category" value={data.alert.category} addFilter={this.addFilter} />
                                    <EventField field_name="Severity" field="alert.severity" value={data.alert.severity} addFilter={this.addFilter} />
                                    <EventField field_name="Revision" field="alert.rev" value={data.alert.rev} addFilter={this.addFilter} />
                                    {data.alert.tag && <EventField field_name="Tagged" field="alert.tag" value={data.alert.tag} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>

                    <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>IP and basic information</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {data.net_info && data.net_info.src_agg && <EventField field_name="Source Network" field="net_info.src_agg" value={data.net_info.src_agg} addFilter={this.addFilter} />}
                                    <EventField field_name="Source IP" field="src_ip" value={data.src_ip} addFilter={this.addFilter} />
                                    <EventField field_name="Source port" field="src_port" value={data.src_port} addFilter={this.addFilter} />
                                    {data.net_info && data.net_info.dest_agg && <EventField field_name="Destination Network" field="net_info.dest_agg" value={data.net_info.dest_agg} addFilter={this.addFilter} />}
                                    <EventField field_name="Destination IP" field="dest_ip" value={data.dest_ip} addFilter={this.addFilter} />
                                    <EventField field_name="Destination port" field="dest_port" value={data.dest_port} addFilter={this.addFilter} />
                                    <EventField field_name="IP protocol" field="proto" value={data.proto} addFilter={this.addFilter} />
                                    {data.app_proto && <EventField field_name="Application protocol" field="app_proto" value={data.app_proto} addFilter={this.addFilter} />}
                                    {data.app_proto_orig && <EventField field_name="Original application protocol" field="app_proto_orig" value={data.app_proto_orig} addFilter={this.addFilter} />}
                                    <EventField field_name="Probe" field="host" value={data.host} addFilter={this.addFilter} />
                                </dl>
                            </div>
                        </div>
                    </Col>

                    {hasLateralOrTarget && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>Attack vector and lateral movement</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {hasTarget && <React.Fragment>
                                        {sourceNetwork}
                                        <EventField field_name="Source IP" field="alert.source.ip" value={data.alert.source.ip} addFilter={this.addFilter} />
                                        <EventField field_name="Source port" field="alert.source.port" value={data.alert.source.port} addFilter={this.addFilter} />
                                        {targetNetwork}
                                        <EventField field_name="Target IP" field="alert.target.ip" value={data.alert.target.ip} addFilter={this.addFilter} />
                                        <EventField field_name="Target port" field="alert.target.port" value={data.alert.target.port} addFilter={this.addFilter} />
                                    </React.Fragment>}
                                    {hasLateral && <EventField field_name="Lateral movement" field="alert.lateral" value={data.alert.lateral} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                </Row>
                <Row>
                    {data.http !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>HTTP</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    <EventField field_name="Host" field="http.hostname" value={data.http.hostname} addFilter={this.addFilter} />
                                    <EventField field_name="URL" field="http.url" value={data.http.url} addFilter={this.addFilter} />
                                    {data.http.status !== undefined && <EventField field_name="Status" field="http.status" value={data.http.status} addFilter={this.addFilter} />}
                                    <EventField field_name="Method" field="http.http_method" value={data.http.http_method} addFilter={this.addFilter} />
                                    <EventField field_name="User Agent" field="http.http_user_agent" value={data.http.http_user_agent} addFilter={this.addFilter} />
                                    {data.http.http_refer !== undefined && <EventField field_name="Referrer" field="http.http_refer" value={data.http.http_refer} addFilter={this.addFilter} />}
                                    {data.http.http_port !== undefined && <EventField field_name="Port" field="http.http_port" value={data.http.http_port} addFilter={this.addFilter} />}
                                    {data.http.http_content_type !== undefined && <EventField field_name="Content Type" field="http.http_content_type" value={data.http.http_content_type} addFilter={this.addFilter} />}
                                    {data.http.length !== undefined && <EventField field_name="Length" field="http.http_length" value={data.http.length} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.tls !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>TLS</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    <EventField field_name="Subject" field="tls.subject" value={data.tls.subject} addFilter={this.addFilter} />
                                    <EventField field_name="Issuer" field="tls.issuerdn" value={data.tls.issuerdn} addFilter={this.addFilter} />
                                    <EventField field_name="Server Name Indication" field="tls.sni" value={data.tls.sni} addFilter={this.addFilter} />
                                    <EventField field_name="Not Before" field="tls.notbefore" value={data.tls.notbefore} addFilter={this.addFilter} />
                                    <EventField field_name="Not After" field="tls.notafter" value={data.tls.notafter} addFilter={this.addFilter} />
                                    {(data.tls.ja3 && data.tls.ja3.hash !== undefined) && <EventField field_name="JA3" field="tls.ja3.hash" value={data.tls.ja3.hash} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.smtp !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>SMTP</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {(data.smtp.mail_from !== undefined) && <EventField field_name="From" field="smtp.mail_from" value={data.smtp.mail_from} addFilter={this.addFilter} />}
                                    {(data.smtp.rcpt_to !== undefined) && data.smtp.rcpt_to.map((mail, idx) => (
                                        // eslint-disable-next-line react/no-array-index-key
                                        <EventField field_name="To" field="smtp.rcpt_to" value={mail} addFilter={this.addFilter} key={`to-${idx}`} />
                                    ))}
                                    {(data.smtp.helo !== undefined) && <EventField field_name="Helo" field="smtp.helo" value={data.smtp.helo} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.ssh !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>SSH</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {data.ssh.client && <React.Fragment>
                                        <EventField field_name="Client Software" field="ssh.client.software_version" value={data.ssh.client.software_version} addFilter={this.addFilter} />
                                        <EventField field_name="Client Version" field="ssh.client.proto_version" value={data.ssh.client.proto_version} addFilter={this.addFilter} />
                                    </React.Fragment>}
                                    {data.ssh.server && <React.Fragment>
                                        <EventField field_name="Server Software" field="ssh.server.software_version" value={data.ssh.server.software_version} addFilter={this.addFilter} />
                                        <EventField field_name="Server Version" field="ssh.server.proto_version" value={data.ssh.server.proto_version} addFilter={this.addFilter} />
                                    </React.Fragment>}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.smb !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>SMB</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {data.smb.command !== undefined && <EventField field_name="Command"
                                        field="smb.command"
                                        value={data.smb.command}
                                        addFilter={this.addFilter}
                                    />}
                                    {data.smb.status !== undefined && <EventField field_name="Status"
                                        field="smb.status"
                                        value={data.smb.status}
                                        addFilter={this.addFilter}
                                    />}
                                    {data.smb.filename !== undefined && <EventField field_name="Filename"
                                        field="smb.filename"
                                        value={data.smb.filename}
                                        addFilter={this.addFilter}
                                    />}
                                    {data.smb.share !== undefined && <EventField field_name="Share"
                                        field="smb.share"
                                        value={data.smb.share}
                                        addFilter={this.addFilter}
                                    />}
                                    {data.smb.session_id !== undefined && <EventField field_name="Session ID"
                                        field="smb.session_id"
                                        value={data.smb.session_id}
                                        addFilter={this.addFilter}
                                    />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {(data.dns !== undefined && dnsQuery !== undefined) && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>DNS</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {dnsQuery.rrname !== undefined && <EventField field_name="Queried Name"
                                        field="dns.query.rrname"
                                        value={dnsQuery.rrname}
                                        addFilter={this.addFilter}
                                    />}
                                    {dnsQuery.rrtype !== undefined && <EventField field_name="Queried Type"
                                        field="dns.query.rrtype"
                                        value={dnsQuery.rrtype}
                                        addFilter={this.addFilter}
                                    />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data['ftp-data'] !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>FTP data</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {data['ftp-data'].command !== undefined && <EventField field_name="Command" field="ftp-data.command" value={data['ftp-data'].command} addFilter={this.addFilter} />}
                                    {data['ftp-data'].filename !== undefined && <EventField field_name="Filename" field="ftp-data.filename" value={data['ftp-data'].filename} addFilter={this.addFilter} />}
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.flow !== undefined && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>Flow</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    <EventField field_name="Flow start" field="flow.start" value={data.flow.start} addFilter={this.addFilter} />
                                    <EventField field_name="Pkts to server" field="flow.pkts_toserver" value={data.flow.pkts_toserver} addFilter={this.addFilter} />
                                    <EventField field_name="Bytes to server" field="flow.bytes_toserver" value={data.flow.bytes_toserver} addFilter={this.addFilter} />
                                    <EventField field_name="Pkts to client" field="flow.pkts_toclient" value={data.flow.pkts_toclient} addFilter={this.addFilter} />
                                    <EventField field_name="Bytes to client" field="flow.bytes_toclient" value={data.flow.bytes_toclient} addFilter={this.addFilter} />
                                </dl>
                            </div>
                        </div>
                    </Col>}
                    {data.alert.metadata && <Col sm={4}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>Signature metadata</h5>
                            </div>
                            <div className="card-pf-body">
                                <dl className="dl-horizontal">
                                    {
                                        Object.entries(data.alert.metadata).map((field) => {
                                            const value = (field[1] === null) ? '' : field[1].join(', ');
                                            const key = (field[0] === null) ? '' : field[0];
                                            return (
                                                <React.Fragment key={key}>
                                                    <EventField field_name={key} field={`alert.metadata.${key}`} value={value} addFilter={this.addFilter} />
                                                </React.Fragment>
                                            )
                                        })
                                    }
                                </dl>
                            </div>
                        </div>
                    </Col>}
                </Row>
                {data.payload_printable && <Row>
                    <Col sm={12}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>Payload printable</h5>
                            </div>
                            <div className="card-pf-body">
                                <pre style={{ maxHeight: '12pc' }}>{data.payload_printable}</pre>
                            </div>
                        </div>

                    </Col>
                </Row>}
                {data.http && <Row>
                    {data.http.http_request_body_printable && <Col sm={6}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>HTTP request body</h5>
                            </div>
                            <div className="card-pf-body">
                                <pre style={{ maxHeight: '12pc' }}>{data.http.http_request_body_printable}</pre>
                            </div>
                        </div>
                    </Col>}
                    {data.http.http_response_body_printable && <Col sm={6}>
                        <div className="card-pf">
                            <div className="card-pf-heading">
                                <h5>HTTP response body</h5>
                            </div>
                            <div className="card-pf-body">
                                <pre style={{ maxHeight: '12pc' }}>{data.http.http_response_body_printable}</pre>
                            </div>
                        </div>
                    </Col>}
                </Row>}
                <Row>
                    <Col sm={12}>
                        <strong>Full JSON event</strong>
                        <ReactJson
                            name={false}
                            src={data}
                            displayDataTypes={false}
                            displayObjectSize={false}
                            collapseStringsAfterLength={150}
                            collapsed
                        />
                    </Col>
                </Row>
            </ListViewItem>
        );
    }
}
AlertInList.propTypes = {
    id: PropTypes.any,
    data: PropTypes.any,
    addFilter: PropTypes.func,
};
