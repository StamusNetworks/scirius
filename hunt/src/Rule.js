/* eslint-disable react/no-danger,jsx-a11y/click-events-have-key-events,jsx-a11y/no-static-element-interactions */
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
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner, PAGINATION_VIEW, Modal, DropdownKebab, MenuItem, Icon } from 'patternfly-react';
import { ListGroup, ListGroupItem, Badge } from 'react-bootstrap';
import axios from 'axios';
import store from 'store';
import md5 from 'md5';
import SciriusChart from './SciriusChart';
import * as config from './config/Api';
import { HuntFilter } from './HuntFilter';
import { HuntList } from './HuntList';
import HuntPaginationRow from './HuntPaginationRow';
import RuleStatus from './RuleStatus';
import RuleToggleModal from './RuleToggleModal';
import RuleEditKebab from './RuleEditKebab';
import { HuntDashboard } from './Dashboard';
import EventValue from './EventValue';
import { buildQFilter } from './helpers/buildQFilter';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';


const statsCache = {};
export const RuleSortFields = [
    {
        id: 'created',
        title: 'Created',
        isNumeric: true,
        defaultAsc: false,
    },
    {
        id: 'hits',
        title: 'Alerts',
        isNumeric: true,
        defaultAsc: false,
    },
    {
        id: 'msg',
        title: 'Message',
        isNumeric: false,
        defaultAsc: true,
    },
    {
        id: 'updated',
        title: 'Updated',
        isNumeric: true,
        defaultAsc: false,
    }
];

// eslint-disable-next-line react/prefer-stateless-function
export class RuleInList extends React.Component {
    render() {
        const { category } = this.props.data;
        const source = this.props.state.sources[category.source];
        let catTooltip = category.name;
        if (source && source.name) {
            catTooltip = `${source.name}: ${category.name}`;
        }
        const kebabConfig = { rule: this.props.data };
        return (
            <ListViewItem
                key={this.props.data.sid}
                // eslint-disable-next-line jsx-a11y/click-events-have-key-events,jsx-a11y/no-static-element-interactions,jsx-a11y/interactive-supports-focus
                actions={[<a role="button" key={`actions-${this.props.data.sid}`} onClick={() => { this.props.SwitchPage(this.props.data); }}><Icon type="fa" name="search-plus" /> </a>, <RuleEditKebab key={`kebab-${this.props.data.sid}`} config={kebabConfig} rulesets={this.props.rulesets} />]}
                leftContent={<ListViewIcon name="envelope" />}
                additionalInfo={[<ListViewInfoItem key={`created-${this.props.data.sid}`}><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                    <ListViewInfoItem key={`updated-${this.props.data.sid}`}><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                    <ListViewInfoItem key={`category-${this.props.data.sid}`}><p data-toggle="tooltip" title={catTooltip}>Category: {category.name}</p></ListViewInfoItem>,
                    <ListViewInfoItem key={`hits-${this.props.data.sid}`}><Spinner loading={this.props.data.hits === undefined} size="xs"><p>Alerts <span className="badge">{this.props.data.hits}</span></p></Spinner></ListViewInfoItem>
                ]}
                heading={this.props.data.sid}
                description={this.props.data.msg}
            >
                {this.props.data.timeline && <Row>
                    <Col sm={11}>
                        <div className="container-fluid">
                            <div className="row">
                                <div className="SigContent" dangerouslySetInnerHTML={{ __html: this.props.data.content }}></div>
                            </div>
                            <div className="row">
                                <div className="col-md-12">
                                    <SciriusChart data={this.props.data.timeline}
                                        axis={{
                                            x: {
                                                type: 'timeseries',
                                                localtime: true,
                                                min: this.props.from_date,
                                                max: Date.now(),
                                                tick: { fit: false, rotate: 15, format: '%Y-%m-%d %H:%M' }
                                            }
                                        }}
                                    />
                                </div>
                            </div>
                            <div className="row">
                                <div className="col-md-4">
                                    <h4>Probes</h4>
                                    <ListGroup>
                                        {this.props.data.probes.map((item) => (
                                            <ListGroupItem key={item.probe}>
                                                <EventValue field={'host'}
                                                    value={item.probe}
                                                    addFilter={this.props.addFilter}
                                                    right_info={<Badge>{item.hits}</Badge>}
                                                />
                                            </ListGroupItem>))}
                                    </ListGroup>
                                </div>
                            </div>
                        </div>
                    </Col>
                </Row>}
            </ListViewItem>
        );
    }
}
RuleInList.propTypes = {
    data: PropTypes.any,
    state: PropTypes.any,
    rulesets: PropTypes.any,
    from_date: PropTypes.any,
    SwitchPage: PropTypes.any,
    addFilter: PropTypes.any,
};

// eslint-disable-next-line react/prefer-stateless-function,react/no-multi-comp
export class RuleCard extends React.Component {
    render() {
        const { category } = this.props.data;
        const source = this.props.state.sources[category.source];
        let catTooltip = category.name;
        if (source && source.name) {
            catTooltip = `${source.name}: ${category.name}`;
        }
        let imported;
        if (!this.props.data.created) {
            [imported] = this.props.data.imported_date.split('T');
        }
        return (
            <div className="col-xs-6 col-sm-4 col-md-4">
                <div className="card-pf rule-card">
                    <div className="card-pf-heading">
                        <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.data.msg}>{this.props.data.msg}</h2>
                    </div>
                    <div className="card-pf-body">
                        <div className="container-fluid">
                            <div className="row">
                                <div className="col-md-5 truncate-overflow" data-toggle="tooltip" title={catTooltip}>Cat: {category.name}</div>
                                <div className="col-md-4">
                                    {this.props.data.created && <p>Created: {this.props.data.created}</p>}
                                    {!this.props.data.created && <p>Imported: {imported}</p>}
                                </div>
                                <div className="col-md-3">Alerts
                                    <Spinner loading={this.props.data.hits === undefined} size="xs">
                                        <span className="badge">{this.props.data.hits}</span>
                                    </Spinner>
                                </div>
                            </div>
                        </div>
                        <Spinner loading={this.props.data.hits === undefined} size="xs">
                            {this.props.data.timeline && <div className="chart-pf-sparkline">
                                <SciriusChart data={this.props.data.timeline}
                                    axis={{
                                        x: {
                                            type: 'timeseries',
                                            localtime: true,
                                            min: this.props.from_date,
                                            max: Date.now(),
                                            show: false,
                                            tick: { fit: true, rotate: 15, format: '%Y-%m-%d %H:%M' }
                                        },
                                        y: { show: false }
                                    }}
                                    legend={{
                                        show: false
                                    }}
                                    size={{ height: 60 }}
                                    point={{ show: false }}
                                />
                            </div>}
                            {!this.props.data.timeline && <div className="no-sparkline">
                                <p>No alert</p>
                            </div>}
                        </Spinner>
                        <div>
            SID: <strong>{this.props.data.sid}</strong>
                            <span className="pull-right">
                                <a onClick={() => { this.props.SwitchPage(this.props.data); }}
                                    style={{ cursor: 'pointer' }}
                                >
                                    <Icon type="fa" name="search-plus" />
                                </a>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        );
    }
}
RuleCard.propTypes = {
    data: PropTypes.any,
    state: PropTypes.any,
    from_date: PropTypes.any,
    SwitchPage: PropTypes.any,
};

function buildTimelineDataSet(tdata) {
    const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
    for (let key = 0; key < tdata.length; key += 1) {
        timeline.columns[0].push(tdata[key].key);
        timeline.columns[1].push(tdata[key].doc_count);
    }
    return timeline;
}

function buildProbesSet(data) {
    const probes = [];
    for (let probe = 0; probe < data.length; probe += 1) {
        probes.push({ probe: data[probe].key, hits: data[probe].doc_count });
    }
    return probes;
}

function processHitsStats(res, rules, updateCallback) {
    for (let rule = 0; rule < rules.length; rule += 1) {
        let found = false;
        for (let info = 1; info < res.data.length; info += 1) {
            if (res.data[info].key === rules[rule].sid) {
                rules[rule].timeline = buildTimelineDataSet(res.data[info].timeline.buckets);
                rules[rule].probes = buildProbesSet(res.data[info].probes.buckets);
                rules[rule].hits = res.data[info].doc_count;
                found = true;
                break;
            }
        }
        if (found === false) {
            rules[rule].hits = 0;
            rules[rule].probes = [];
            rules[rule].timeline = undefined;
        }
    }
    if (updateCallback) {
        updateCallback(rules);
    }
}

export function updateHitsStats(rules, pFromDate, updateCallback, qfilter) {
    const sids = Array.from(rules, (x) => x.sid).join();
    const fromDate = `&from_date=${pFromDate}`;
    let url = config.API_URL + config.ES_SIGS_LIST_PATH + sids + fromDate;
    if (qfilter) {
        url += `&filter=${qfilter}`;
    }
    if (typeof statsCache[encodeURI(url)] !== 'undefined') {
        processHitsStats(statsCache[encodeURI(url)], rules, updateCallback);
        return;
    }
    axios.get(url).then((res) => {
        /* we are going O(n2), we should fix that */
        statsCache[encodeURI(url)] = res;
        processHitsStats(res, rules, updateCallback);
    });
}

// eslint-disable-next-line react/no-multi-comp
export class RulePage extends React.Component {
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

        if (rule !== undefined) {
            updateHitsStats([rule], this.props.from_date, this.updateRuleState, qfilter);
            axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats&field=app_proto&from_date=${this.props.from_date}&sid=${this.props.rule.sid}`)
            .then((res) => {
                this.updateExtInfo(res.data);
            });
            this.fetchRuleStatus(rule.sid);
        } else {
            axios.get(`${config.API_URL}${config.RULE_PATH}${sid}/?highlight=true`).then(
                (res) => {
                    updateHitsStats([res.data], this.props.from_date, this.updateRuleState, qfilter);
                    axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats&field=app_proto&from_date=${this.props.from_date}&sid=${sid}`)
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
        if ((prevProps.from_date !== this.props.from_date) || (prevProps.filters.length !== this.props.filters.length)) {
            const rule = JSON.parse(JSON.stringify(this.state.rule));

            if (rule) {
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
                for (let key = 0; key < res.data.length; key += 1) {
                    res.data[key].pk = key;
                    res.data[key].content = rescontent.data[key];
                    rstatus.push(res.data[key]);
                }
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
                    {this.state.rule && <div>
                        <h1>{this.state.rule.msg}
                            <span className="pull-right">
                                { (this.state.rule && this.state.rule.hits !== undefined) && <span className="label label-primary">{this.state.rule.hits} hit{this.state.rule.hits > 1 && 's'}</span>}
                                <RuleEditKebab config={this.state} rulesets={this.props.rulesets} refresh_callback={this.updateRuleStatus} />
                            </span>
                        </h1>
                        <div className="container-fluid container-cards-pf">
                            <div className="row">
                                <div className="SigContent" dangerouslySetInnerHTML={{ __html: this.state.rule.content }}></div>
                                {this.state.rule.timeline && <SciriusChart
                                    data={this.state.rule.timeline}
                                    axis={{
                                        x: {
                                            type: 'timeseries',
                                            localtime: true,
                                            min: this.props.from_date,
                                            max: Date.now(),
                                            tick: {
                                                fit: false,
                                                rotate: 15,
                                                format: '%Y-%m-%d %H:%M'
                                            }
                                        }
                                    }}
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
                            <Row>
                                {this.state.rule_references && this.state.rule_references.length > 0 && <div className="col-xs-6 col-sm-4 col-md-4">
                                    <div className="card-pf card-pf-accented card-pf-aggregate-status">
                                        {/* <div class="panel-heading">
                                            <h2 class="panel-title">References</h2>
                                        </div> */}
                                        <h2 className="card-pf-title">
                                            <span className="fa" />References
                                        </h2>
                                        <div className="card-pf-body">
                                            {this.state.rule_references.map((reference) => {
                                                if (reference.url !== undefined) {
                                                    return (
                                                        <p key={reference.url}><a href={reference.url} target="_blank">{`${reference.key[0].toUpperCase() + reference.key.substring(1)}: ${reference.value}`}</a></p>
                                                    );
                                                }
                                                return null;
                                            })}
                                        </div>
                                    </div>
                                </div>}
                            </Row>
                        </div>
                    </div>}
                </Spinner>

                <Modal show={!(this.state.moreModal === null)} onHide={() => { this.hideMoreModal() }}>

                    <Modal.Header>More results <Modal.CloseButton closeText={'Close'} onClick={() => { this.hideMoreModal() }} /> </Modal.Header>
                    <Modal.Body>
                        <div className="hunt-stat-body">
                            <ListGroup>
                                {this.state.moreResults.map((item) => (<ListGroupItem key={item.key}>
                                    {this.state.moreModal && <EventValue field={this.state.moreModal.i} value={item.key} addFilter={this.addFilter} right_info={<Badge>{item.doc_count}</Badge>} />}
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

// eslint-disable-next-line react/no-multi-comp
export class HuntStat extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: [] };
        this.url = '';
        this.updateData = this.updateData.bind(this);
        this.addFilter = this.addFilter.bind(this);
    }

    componentDidMount() {
        this.updateData();
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date) {
            this.updateData();
        }
        if (prevProps.filters.length !== this.props.filters.length) {
            this.updateData();
        }
    }

    updateData() {
        let qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
        if (qfilter) {
            qfilter = `&qfilter=${qfilter}`;
        } else {
            qfilter = '';
        }

        this.url = `${config.API_URL}${config.ES_BASE_PATH}field_stats&field=${this.props.item}&from_date=${this.props.from_date}&page_size=30${qfilter}`;

        axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats&field=${this.props.item}&from_date=${this.props.from_date}&page_size=5${qfilter}`)
        .then((res) => {
            this.setState({ data: res.data });
        });
    }

    addFilter(key, value, negated) {
        this.props.addFilter(key, value, negated);
    }

    render() {
        let colVal = 'col-md-3';
        if (this.props.col) {
            colVal = `col-md-${this.props.col}`;
        }
        if (this.state.data && this.state.data.length) {
            return (
                <div className={colVal}>
                    <div className="card-pf rule-card">
                        <div className="card-pf-heading">
                            <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.title}>{this.props.title}</h2>
                            {this.state.data.length === 5 && <DropdownKebab id={`more-${this.props.item}`} pullRight={false}>
                                <MenuItem onClick={() => this.props.loadMore(this.props.item, this.url)} data-toggle="modal">Load more results</MenuItem>
                            </DropdownKebab>}
                        </div>
                        <div className="card-pf-body">
                            <ListGroup>
                                {this.state.data.map((item) => (
                                    <ListGroupItem key={item.key}>
                                        <EventValue field={this.props.item}
                                            value={item.key}
                                            addFilter={this.addFilter}
                                            right_info={<Badge>{item.doc_count}</Badge>}
                                        />
                                    </ListGroupItem>)
                                )}
                            </ListGroup>
                        </div>
                    </div>
                </div>
            );
        }
        return null;
    }
}
HuntStat.propTypes = {
    from_date: PropTypes.any,
    title: PropTypes.any,
    filters: PropTypes.any,
    col: PropTypes.any,
    item: PropTypes.any,
    systemSettings: PropTypes.any,
    loadMore: PropTypes.func,
    addFilter: PropTypes.func,
};

export class RulesList extends HuntList {
    constructor(props) {
        super(props);

        const huntFilters = store.get('huntFilters');
        const rulesFilters = (typeof huntFilters !== 'undefined' && typeof huntFilters.ruleslist !== 'undefined') ? huntFilters.ruleslist.data : [];
        this.state = {
            rules: [],
            sources: [],
            rulesets: [],
            count: 0,
            loading: true,
            refresh_data: false,
            view: 'rules_list',
            display_toggle: true,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rulesFilters,
            supported_actions: []
        };
        this.cache = {};
        this.cachePage = 1;
        this.updateRulesState = this.updateRulesState.bind(this);
        this.fetchHitsStats = this.fetchHitsStats.bind(this);
        this.displayRule = this.displayRule.bind(this);
        this.RuleUpdateFilter = this.RuleUpdateFilter.bind(this);
    }

    buildFilter(filters) {
        const lFilters = {};
        for (let i = 0; i < filters.length; i += 1) {
            if (filters[i].id !== 'probe' && filters[i].id !== 'alert.tag') {
                if (filters[i].id in lFilters) {
                    lFilters[filters[i].id] += `,${filters[i].value}`;
                } else {
                    lFilters[filters[i].id] = filters[i].value;
                }
            }
        }
        let stringFilters = '';
        const objKeys = Object.keys(lFilters);
        for (let k = 0; k < objKeys.length; k += 1) {
            stringFilters += `&${objKeys[k]}=${lFilters[objKeys[k]]}`;
        }
        const qfilter = buildQFilter(filters, this.props.systemSettings);
        if (qfilter) {
            stringFilters += `&qfilter=${qfilter}`;
        }
        return stringFilters;
    }

    updateRulesState(rules) {
        this.setState({ rules });
    }

    buildTimelineDataSet = (tdata) => {
        const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
        for (let key = 0; key < tdata.length; key += 1) {
            timeline.columns[0].push(tdata[key].date);
            timeline.columns[1].push(tdata[key].hits);
        }
        return timeline;
    }

    buildHitsStats(rules) {
        for (let rule = 0; rule < rules.length; rule += 1) {
            rules[rule].timeline = this.buildTimelineDataSet(rules[rule].timeline_data);
            // rules[rule].timeline_data = undefined;
        }
        this.updateRulesState(rules);
    }

    fetchHitsStats(rules, filters) {
        const qfilter = buildQFilter(filters, this.props.systemSettings);
        updateHitsStats(rules, this.props.from_date, this.updateRulesState, qfilter);
    }

    processRulesData(RuleRes, SrcRes, filters) {
        const sourcesArray = SrcRes.data.results;
        const sources = {};
        this.setState({ net_error: undefined });
        for (let i = 0; i < sourcesArray.length; i += 1) {
            const src = sourcesArray[i];
            sources[src.pk] = src;
        }
        this.setState({
            count: RuleRes.data.count,
            rules: RuleRes.data.results,
            sources,
            loading: false,
            refresh_data: false
        });
        if (RuleRes.data.results.length > 0) {
            if (!RuleRes.data.results[0].timeline_data) {
                this.fetchHitsStats(RuleRes.data.results, filters);
            } else {
                this.buildHitsStats(RuleRes.data.results);
            }
        }
    }

    displayRule(rule) {
        this.setState({ display_rule: rule });
        const activeFilters = [...this.props.filters, {
            label: `alert.signature_id: ${rule.sid}`, id: 'alert.signature_id', value: rule.sid, query: 'filter', negated: false
        }];
        this.RuleUpdateFilter(activeFilters);
    }

    fetchData(rulesStat, filters) {
        const stringFilters = this.buildFilter(filters);
        const hash = md5(`${rulesStat.pagination.page}|${rulesStat.pagination.perPage}|${this.props.from_date}|${rulesStat.sort.id}|${rulesStat.sort.asc}|${stringFilters}`);
        if (typeof this.cache[hash] !== 'undefined') {
            this.processRulesData(this.cache[hash].RuleRes, this.cache[hash].SrcRes, this.cache[hash].filters);
            return;
        }

        this.setState({ refresh_data: true, loading: true });
        axios.all([
            axios.get(`${config.API_URL + config.RULE_PATH}?${this.buildListUrlParams(rulesStat)}&from_date=${this.props.from_date}&highlight=true${stringFilters}`),
            axios.get(`${config.API_URL + config.SOURCE_PATH}?page_size=100`),
        ])
        .then(axios.spread((RuleRes, SrcRes) => {
            this.cachePage = rulesStat.pagination.page;

            this.cache[hash] = { RuleRes, SrcRes, filters };
            this.processRulesData(RuleRes, SrcRes, filters);
        })).catch((e) => {
            this.setState({ net_error: e, loading: false });
        });
    }

    componentDidMount() {
        const sid = this.findSID(this.props.filters);
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
                this.setState({ rulesets: res.data.results });
            });
        }
        if (sid !== undefined) {
            // eslint-disable-next-line react/no-did-mount-set-state
            this.setState({
                display_rule: sid, view: 'rule', display_toggle: false, loading: false
            });
        } else {
            this.fetchData(this.props.config, this.props.filters);
        }
        const huntFilters = store.get('huntFilters');
        axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
            (res) => {
                const fdata = [];
                for (let i = 0; i < res.data.length; i += 1) {
                    /* Allow ES and rest filters */
                    if (['filter', 'rest'].indexOf(res.data[i].queryType) !== -1) {
                        if (res.data[i].filterType !== 'hunt') {
                            fdata.push(res.data[i]);
                        }
                    }
                }
                const currentCheckSum = md5(JSON.stringify(fdata));
                if ((typeof huntFilters === 'undefined' || typeof huntFilters.ruleslist === 'undefined') || huntFilters.ruleslist.checkSum !== currentCheckSum) {
                    store.set('huntFilters', {
                        ...huntFilters,
                        ruleslist: {
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

    findSID = (filters) => {
        let foundSid;
        for (let i = 0; i < filters.length; i += 1) {
            if (filters[i].id === 'alert.signature_id') {
                foundSid = filters[i].value;
                break;
            }
        }
        return foundSid;
    }

    RuleUpdateFilter(filters) {
        // iterate on filter, if we have a sid we display the rule page
        const foundSid = this.findSID(filters);
        if (foundSid !== undefined) {
            this.setState({ view: 'rule', display_toggle: false, display_rule: foundSid });
        } else {
            this.setState({ view: 'rules_list', display_toggle: true, display_rule: undefined });
        }
        this.UpdateFilter(filters, this.cachePage);
    }


    render() {
        return (
            <div className="RulesList HuntList">
                {this.state.net_error !== undefined && <div className="alert alert-danger">Problem with backend: {this.state.net_error.message}</div>}
                <HuntFilter ActiveFilters={this.props.filters}
                    config={this.props.config}
                    ActiveSort={this.props.config.sort}
                    UpdateFilter={this.RuleUpdateFilter}
                    UpdateSort={this.UpdateSort}
                    setViewType={this.setViewType}
                    filterFields={this.state.rulesFilters}
                    sort_config={RuleSortFields}
                    displayToggle={this.state.display_toggle}
                    actionsButtons={this.actionsButtons}
                    queryType={['filter', 'rest']}
                />
                {this.state.view === 'rules_list' && this.props.config.view_type === 'list' && <React.Fragment>
                    <Spinner loading={this.state.loading}>
                    </Spinner>

                    <ListView>
                        {this.state.rules.map((rule) => (
                            <RuleInList key={rule.sid} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.displayRule} addFilter={this.addFilter} rulesets={this.state.rulesets} />
                        ))}
                    </ListView>
                </React.Fragment>}
                {this.state.view === 'rules_list' && this.props.config.view_type === 'card' && <div className="container-fluid container-cards-pf">
                    <div className="row row-cards-pf">
                        {this.state.rules.map((rule) => (
                            <RuleCard key={rule.pk} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.displayRule} addFilter={this.addFilter} />
                        ))}
                    </div>
                </div>}
                {this.state.view === 'rules_list' && <HuntPaginationRow
                    viewType={PAGINATION_VIEW.LIST}
                    pagination={this.props.config.pagination}
                    onPaginationChange={this.handlePaginationChange}
                    amountOfPages={Math.ceil(this.state.count / this.props.config.pagination.perPage)}
                    pageInputValue={this.props.config.pagination.page}
                    itemCount={this.state.count - 1} // used as last item
                    itemsStart={(this.props.config.pagination.page - 1) * this.props.config.pagination.perPage}
                    itemsEnd={Math.min((this.props.config.pagination.page * this.props.config.pagination.perPage) - 1, this.state.count - 1)}
                    onFirstPage={this.onFirstPage}
                    onNextPage={this.onNextPage}
                    onPreviousPage={this.onPrevPage}
                    onLastPage={this.onLastPage}
                />}
                {this.state.view === 'rule' && <RulePage systemSettings={this.props.systemSettings} rule={this.state.display_rule} config={this.props.config} filters={this.props.filters} from_date={this.props.from_date} UpdateFilter={this.RuleUpdateFilter} addFilter={this.addFilter} rulesets={this.state.rulesets} />}
                {this.state.view === 'dashboard' && <HuntDashboard />}

                <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.config} filters={this.props.filters} close={this.closeAction} rulesets={this.state.rulesets} />
            </div>
        );
    }
}
