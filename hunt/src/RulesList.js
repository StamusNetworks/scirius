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
import { ListView, Spinner, PAGINATION_VIEW } from 'patternfly-react';
import axios from 'axios';
import store from 'store';
import md5 from 'md5';
import * as config from './config/Api';
import { HuntFilter } from './HuntFilter';
import { HuntList } from './HuntList';
import HuntPaginationRow from './HuntPaginationRow';
import RuleToggleModal from './RuleToggleModal';
import RuleCard from './RuleCard';
import { HuntDashboard } from './Dashboard';
import { buildQFilter } from './helpers/buildQFilter';
import RulePage from './RulePage';
import RuleInList from './RuleInList';

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
