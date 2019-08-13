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
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { Spinner, PAGINATION_VIEW } from 'patternfly-react';
import axios from 'axios';
import store from 'store';
import md5 from 'md5';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from 'hunt_common/buildQFilter';
import HuntFilter from '../../HuntFilter';
import HuntPaginationRow from '../../HuntPaginationRow';
import RuleToggleModal from '../../RuleToggleModal';
import RuleCard from '../../RuleCard';
import DashboardPage from '../DashboardPage';
import RulePage from '../../RulePage';
import RuleInList from '../../RuleInList';
import List from '../../components/List/index';
import ErrorHandler from '../../components/Error';
import { actionsButtons,
    buildListUrlParams,
    loadActions,
    createAction,
    handlePaginationChange,
    onFirstPage,
    onNextPage,
    onPrevPage,
    onLastPage,
    setViewType,
    UpdateSort,
    closeAction,
    updateAlertTag,
    buildFilter } from '../../helpers/common';
import { addFilter, clearFilters, editFilter, removeFilter, makeSelectGlobalFilters } from '../App/stores/global';

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
        for (let info = 0; info < res.data.length; info += 1) {
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
    const url = config.API_URL + config.ES_SIGS_LIST_PATH + sids + fromDate + qfilter;
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

class SignaturesPage extends React.Component {
// export class RulesList extends HuntList {
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
            display_toggle: true,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rulesFilters,
            // eslint-disable-next-line react/no-unused-state
            supported_actions: [],
            updateCache: true
        };
        this.cache = {};
        this.cachePage = 1;
        this.updateRulesState = this.updateRulesState.bind(this);
        this.fetchHitsStats = this.fetchHitsStats.bind(this);
        this.actionsButtons = actionsButtons.bind(this);
        this.buildListUrlParams = buildListUrlParams.bind(this);
        this.loadActions = loadActions.bind(this);
        this.createAction = createAction.bind(this);
        this.handlePaginationChange = handlePaginationChange.bind(this);
        this.onFirstPage = onFirstPage.bind(this);
        this.onNextPage = onNextPage.bind(this);
        this.onPrevPage = onPrevPage.bind(this);
        this.onLastPage = onLastPage.bind(this);
        this.setViewType = setViewType.bind(this);
        this.UpdateSort = UpdateSort.bind(this);
        this.closeAction = closeAction.bind(this);
        this.updateAlertTag = updateAlertTag.bind(this);
        this.buildFilter = buildFilter.bind(this);
    }

    componentDidMount() {
        const sid = this.findSID(this.props.filters);
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
                this.setState({ rulesets: res.data.results });
            });
        }
        if (sid !== undefined) {
            this.setState({
                display_toggle: false, loading: false
            });
        } else {
            this.fetchData(this.props.rules_list, this.props.filtersWithAlert);
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

    componentDidUpdate(prevProps) {
        const filtersChanged = (JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert));
        if (prevProps.from_date !== this.props.from_date || filtersChanged) {
            const sid = this.findSID(this.props.filtersWithAlert);
            if (sid !== undefined) {
                // eslint-disable-next-line react/no-did-update-set-state
                this.setState({
                    display_toggle: false, loading: false
                });
            } else {
                this.fetchData(this.props.rules_list, this.props.filtersWithAlert);
            }
            if (filtersChanged) {
                this.loadActions(this.props.filtersWithAlert);
            }
        }
    }

    buildTimelineDataSet = (tdata) => {
        const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
        for (let key = 0; key < tdata.length; key += 1) {
            timeline.columns[0].push(tdata[key].date);
            timeline.columns[1].push(tdata[key].hits);
        }
        return timeline;
    }

    findSID = (filters) => {
        let foundSid;
        for (let i = 0; i < filters.length; i += 1) {
            if (filters[i].id === 'alert.signature_id' && filters[i].negated === false) {
                foundSid = filters[i].value;
                break;
            }
        }
        return foundSid;
    }

    fetchData(rulesStat, filters) {
        const stringFilters = this.buildFilter(filters);
        const hash = md5(`${rulesStat.pagination.page}|${rulesStat.pagination.perPage}|${this.props.from_date}|${rulesStat.sort.id}|${rulesStat.sort.asc}|${stringFilters}`);
        if (typeof this.cache[hash] !== 'undefined') {
            this.processRulesData(this.cache[hash].RuleRes, this.cache[hash].SrcRes, this.cache[hash].filters);
            return;
        }

        this.setState({ loading: true });
        axios.all([
            axios.get(`${config.API_URL + config.RULE_PATH}?${this.buildListUrlParams(rulesStat)}&from_date=${this.props.from_date}&highlight=true${stringFilters}`),
            axios.get(`${config.API_URL + config.SOURCE_PATH}?page_size=100`),
        ])
        .then(axios.spread((RuleRes, SrcRes) => {
            if (this.state.updateCache) {
                this.cachePage = rulesStat.pagination.page;
            } else {
                this.setState({ updateCache: true });
            }

            this.cache[hash] = { RuleRes, SrcRes, filters };
            this.processRulesData(RuleRes, SrcRes, filters);
        })).catch((e) => {
            this.setState({ net_error: e, loading: false });
        });
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
        });
        if (RuleRes.data.results.length > 0) {
            if (!RuleRes.data.results[0].timeline_data) {
                this.fetchHitsStats(RuleRes.data.results, filters);
            } else {
                this.buildHitsStats(RuleRes.data.results);
            }
        }
    }

    fetchHitsStats(rules, filters) {
        const qfilter = buildQFilter(filters, this.props.systemSettings);
        updateHitsStats(rules, this.props.from_date, this.updateRulesState, qfilter);
    }

    buildHitsStats(rules) {
        for (let rule = 0; rule < rules.length; rule += 1) {
            rules[rule].timeline = this.buildTimelineDataSet(rules[rule].timeline_data);
            // rules[rule].timeline_data = undefined;
        }
        this.updateRulesState(rules);
    }

    updateRulesState(rules) {
        this.setState({ rules });
    }

    updateRuleListState(rulesListState) {
        this.props.updateListState(rulesListState);
    }

    render() {
        const displayRule = this.findSID(this.props.filters);
        const view = (displayRule) ? 'rule' : 'rules_list';
        return (
            <div className="RulesList HuntList">
                {this.state.net_error !== undefined && <div className="alert alert-danger">Problem with backend: {this.state.net_error.message}</div>}
                <ErrorHandler>
                    <HuntFilter ActiveFilters={this.props.filters}
                        config={this.props.rules_list}
                        ActiveSort={this.props.rules_list.sort}
                        UpdateSort={this.UpdateSort}
                        setViewType={this.setViewType}
                        filterFields={this.state.rulesFilters}
                        sort_config={RuleSortFields}
                        displayToggle={this.state.display_toggle}
                        actionsButtons={this.actionsButtons}
                        queryType={['filter', 'rest', 'filter_host_id']}
                        page={this.props.page}
                    />
                </ErrorHandler>

                {view === 'rules_list' && <Spinner loading={this.state.loading} />}

                {view === 'rules_list' && <List type={this.props.rules_list.view_type}
                    items={this.state.rules}
                    component={{ list: RuleInList, card: RuleCard }}
                    itemProps={{
                        sources: this.state.sources,
                        from_date: this.props.from_date,
                        switchPage: this.displayRule,
                        rulesets: this.state.rulesets,
                    }}
                />}
                <ErrorHandler>
                    { view === 'rules_list' && <HuntPaginationRow
                        viewType={PAGINATION_VIEW.LIST}
                        pagination={this.props.rules_list.pagination}
                        onPaginationChange={this.handlePaginationChange}
                        amountOfPages={Math.ceil(this.state.count / this.props.rules_list.pagination.perPage)}
                        pageInputValue={this.props.rules_list.pagination.page}
                        itemCount={this.state.count - 1} // used as last item
                        itemsStart={(this.props.rules_list.pagination.page - 1) * this.props.rules_list.pagination.perPage}
                        itemsEnd={Math.min((this.props.rules_list.pagination.page * this.props.rules_list.pagination.perPage) - 1, this.state.count - 1)}
                        onFirstPage={this.onFirstPage}
                        onNextPage={this.onNextPage}
                        onPreviousPage={this.onPrevPage}
                        onLastPage={this.onLastPage}
                    /> }
                    {view === 'rule' && <RulePage systemSettings={this.props.systemSettings} rule={displayRule} config={this.props.rules_list} filters={this.props.filters} from_date={this.props.from_date} rulesets={this.state.rulesets} />}
                    {view === 'dashboard' && <DashboardPage />}
                </ErrorHandler>

                <ErrorHandler>
                    <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.rules_list} filters={this.props.filters} close={this.closeAction} rulesets={this.state.rulesets} />
                </ErrorHandler>
            </div>
        );
    }
}

SignaturesPage.propTypes = {
    systemSettings: PropTypes.any,
    from_date: PropTypes.any,
    filters: PropTypes.any,
    filtersWithAlert: PropTypes.any,
    updateListState: PropTypes.any, // should be removed when redux is implemented
    rules_list: PropTypes.any, // should be removed when redux is implemented
    page: PropTypes.any,
}

const mapStateToProps = createStructuredSelector({
    filters: makeSelectGlobalFilters(),
    filtersWithAlert: makeSelectGlobalFilters(true)
});

const mapDispatchToProps = {
    removeFilter,
    editFilter,
    addFilter,
    clearFilters,
}

export default connect(mapStateToProps, mapDispatchToProps)(SignaturesPage);
