/* eslint-disable react/no-danger */
import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Modal, CloseButton, Row, Badge, ListGroup, ListGroupItem } from 'react-bootstrap';
import { Spinner } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from './helpers/buildQFilter';
import RuleEditKebab from './components/RuleEditKebab';
import SciriusChart from './components/SciriusChart';
import RuleStatus from './RuleStatus';
import HuntStat from './HuntStat';
import EventValue from './components/EventValue';
import { updateHitsStats } from './containers/SignaturesPage/SignaturesPage';

export default class RulePage extends React.Component {
    constructor(props) {
        super(props);
        const rule = JSON.parse(JSON.stringify(this.props.rule));
        if (typeof rule === 'number') {
            this.state = {
                rule: undefined,
                rule_status: undefined,
                sid: rule,
                toggle: { show: false, action: 'Disable' },
                extinfo: { http: false, dns: false, tls: false },
                moreResults: [],
                moreModal: null
            };
        } else {
            rule.timeline = undefined;
            this.state = {
                rule,
                rule_status: undefined,
                sid: rule.sid,
                toggle: { show: false, action: 'Disable' },
                extinfo: { http: false, dns: false, tls: false },
                moreResults: [],
                moreModal: null,
            };
        }
        this.updateRuleState = this.updateRuleState.bind(this);
        this.fetchRuleStatus = this.fetchRuleStatus.bind(this);
        this.updateRuleStatus = this.updateRuleStatus.bind(this);
        this.updateExtInfo = this.updateExtInfo.bind(this);
    }

    componentDidMount() {
        const { rule, sid } = this.state;
        const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);

        if (typeof rule !== 'undefined') {
            updateHitsStats([rule], this.props.from_date, this.updateRuleState, qfilter);
            axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&from_date=${this.props.from_date}&sid=${this.props.rule.sid}`)
            .then((res) => {
                this.updateExtInfo(res.data);
            });
            this.fetchRuleStatus(rule.sid);
        } else {
            axios.get(`${config.API_URL}${config.RULE_PATH}${sid}/?highlight=true`).then(
                (res) => {
                    updateHitsStats([res.data], this.props.from_date, this.updateRuleState, qfilter);
                    axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&from_date=${this.props.from_date}&sid=${sid}`)
                    .then((res2) => {
                        this.updateExtInfo(res2.data);
                    });
                }
            ).catch((error) => {
                if (error.response.status === 404) {
                    // eslint-disable-next-line react/no-unused-state
                    this.setState({ errors: { signature: ['Signature not found'] }, rule: null });
                    return;
                }
                this.setState({ rule: null });
            });
            this.fetchRuleStatus(sid);
        }
    }

    componentDidUpdate(prevProps) {
        const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
        if ((prevProps.from_date !== this.props.from_date) || (JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters))) {
            const rule = JSON.parse(JSON.stringify(this.state.rule));

            if (typeof rule !== 'undefined') {
                updateHitsStats([rule], this.props.from_date, this.updateRuleState, qfilter);
            }
        }
    }

    loadMore = (item, url) => {
        axios.get(url)
        .then((json) => {
            this.setState({ ...this.state, moreModal: item, moreResults: json.data });
        });
    }

    hideMoreModal = () => this.setState({ ...this.state, moreModal: null });

    updateExtInfo(data) {
        if (!data) {
            return;
        }
        const { extinfo } = this.state;
        for (let i = 0; i < data.length; i += 1) {
            if (data[i].key === 'dns') {
                extinfo.dns = true;
            }
            if (data[i].key === 'http') {
                extinfo.http = true;
            }
            if (data[i].key === 'tls') {
                extinfo.tls = true;
            }
        }
        this.setState({ extinfo });
    }

    updateRuleStatus() {
        return this.fetchRuleStatus(this.state.rule.sid);
    }

    fetchRuleStatus(sid) {
        axios.all([
            axios.get(`${config.API_URL + config.RULE_PATH + sid}/status/`),
            axios.get(`${config.API_URL + config.RULE_PATH + sid}/content/?highlight=1`),
            axios.get(`${config.API_URL + config.RULE_PATH + sid}/references/`)
        ]).then(
            ([res, rescontent, referencesContent]) => {
                const rstatus = [];

                Object.keys(res.data).forEach((key) => {
                    res.data[key].pk = key;
                    res.data[key].content = key in rescontent.data ? rescontent.data[key] : 'Rule not included in Ruleset';
                    rstatus.push(res.data[key]);
                });

                this.setState({ rule_status: rstatus });
                this.setState({ rule_references: referencesContent.data });
            }
        );
    }

    updateRuleState(rule) {
        this.setState({ rule: rule[0] });
    }

    render() {
        return (
            <div>
                <Spinner loading={this.state.rule === undefined}>
                    {this.state.rule && <div className="row">
                        <div className="col-xs-12 col-sm-12 col-md-12">
                            <h1>{this.state.rule.msg}
                                <span className="pull-right">
                                    { (this.state.rule && this.state.rule.hits !== undefined) && <span className="label label-primary">{this.state.rule.hits} hit{this.state.rule.hits > 1 && 's'}</span>}
                                    <RuleEditKebab config={this.state} rulesets={this.props.rulesets} refresh_callback={this.updateRuleStatus} />
                                </span>
                            </h1>
                        </div>
                        <div>
                            <div className="container-fluid container-cards-pf">
                                <div className="row">

                                    <div className={(this.state.rule_references !== undefined && this.state.rule_references.length > 0) ? 'col-xs-9 col-sm-9 col-md-9' : 'col-xs-12 col-sm-12 col-md-12'}>
                                        <div className="SigContent" dangerouslySetInnerHTML={{ __html: this.state.rule.content }}></div>
                                    </div>

                                    <div className={(this.state.rule_references !== undefined && this.state.rule_references.length > 0) ? 'col-xs-3 col-sm-3 col-md-3' : 'col-xs-0 col-sm-0 col-md-0'}>
                                        {this.state.rule_references && this.state.rule_references.length > 0 && <div className="card-pf card-pf-accented card-pf-aggregate-status">
                                            <h2 className="card-pf-title">
                                                <span className="fa" />References
                                            </h2>
                                            <div className="card-pf-body">
                                                {this.state.rule_references.map((reference) => {
                                                    if (reference.url !== undefined) {
                                                        return (
                                                            <p key={reference.url}><a href={reference.url} target="_blank">{`${reference.key[0].toUpperCase() + reference.key.substring(1)}: ${reference.value.substring(0, 45)}...`}</a></p>
                                                        );
                                                    }
                                                    return null;
                                                })}
                                            </div>
                                        </div>}
                                    </div>

                                </div>

                                <div className="row">
                                    {this.state.rule.timeline && <SciriusChart
                                        data={this.state.rule.timeline}
                                        from_date={this.props.from_date}
                                    />}
                                </div>
                                {this.state.rule_status !== undefined && <Row>
                                    {
                                        this.state.rule_status.map((rstatus) => (
                                            <RuleStatus rule={this.state.rule} key={rstatus.pk} rule_status={rstatus} />
                                        ))
                                    }
                                </Row>}
                                <div className="row">
                                    <HuntStat systemSettings={this.state.systemSettings} title="Sources" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="src_ip" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat title="Destinations" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="dest_ip" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat title="Probes" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="host" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                </div>
                                {this.state.extinfo.http && <div className="row">
                                    <HuntStat systemSettings={this.state.systemSettings} title="Hostname" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="http.hostname" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat systemSettings={this.state.systemSettings} title="URL" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="http.url" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat systemSettings={this.state.systemSettings} title="User agent" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="http.http_user_agent" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                </div>}
                                {this.state.extinfo.dns && <div className="row">
                                    <HuntStat systemSettings={this.state.systemSettings} title="Name" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="dns.query.rrname" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat systemSettings={this.state.systemSettings} title="Type" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="dns.query.rrtype" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                </div>}
                                {this.state.extinfo.tls && <div className="row">
                                    <HuntStat systemSettings={this.state.systemSettings} title="Subject DN" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="tls.subject" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat systemSettings={this.state.systemSettings} title="SNI" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="tls.sni" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                    <HuntStat systemSettings={this.state.systemSettings} title="Fingerprint" rule={this.state.rule} config={this.props.config} filters={this.props.filters} item="tls.fingerprint" from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter} addFilter={this.props.addFilter} loadMore={this.loadMore} />
                                </div>}
                            </div>
                        </div>
                    </div>}
                </Spinner>

                <Modal show={!(this.state.moreModal === null)} onHide={() => { this.hideMoreModal() }}>

                    <Modal.Header>More results <CloseButton closeText={'Close'} onClick={() => { this.hideMoreModal() }} /> </Modal.Header>
                    <Modal.Body>
                        <div className="hunt-stat-body">
                            <ListGroup>
                                {this.state.moreResults.map((item) => (<ListGroupItem key={item.key}>
                                    {this.state.moreModal && <EventValue field={this.state.moreModal} value={item.key} addFilter={this.props.addFilter} right_info={<Badge>{item.doc_count}</Badge>} />}
                                </ListGroupItem>))}
                            </ListGroup>
                        </div>
                    </Modal.Body>
                </Modal>

            </div>
        );
    }
}
RulePage.propTypes = {
    rule: PropTypes.any,
    systemSettings: PropTypes.any,
    filters: PropTypes.any,
    config: PropTypes.any,
    UpdateFilter: PropTypes.any,
    addFilter: PropTypes.any,
    rulesets: PropTypes.any,
    from_date: PropTypes.any,
};
