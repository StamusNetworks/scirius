/* eslint-disable jsx-a11y/click-events-have-key-events,camelcase,react/sort-comp,no-lonely-if */
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

import React, { Component } from 'react';
import { VerticalNav, Modal } from 'patternfly-react';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';
import axios from 'axios';
import { HuntDashboard } from './Dashboard';
import { HistoryPage } from './History';
import { PAGE_STATE } from './constants';
import SignaturesPage from './containers/SignaturesPage';
import { AlertsList } from './AlertsList';
import { FiltersList } from './Filters';
import SourcePage from './components/SourcePage';
import RulesetPage from './components/RuleSetPage';
import UserNavInfo from './components/UserNavInfo';
import * as config from './config/Api';
import './pygments.css';
// eslint-disable-next-line import/no-unresolved
import './css/App.css';
import sciriusLogo from './img/scirius-by-stamus.svg';
import keymap from './Keymap';

const shortcutManager = new ShortcutManager(keymap);

class HuntApp extends Component {
    constructor(props) {
        super(props);
        this.timer = null;
        const interval = localStorage.getItem('interval');
        let duration = localStorage.getItem('duration');
        let rulesListConf = localStorage.getItem('rules_list');
        let alertsListConf = localStorage.getItem('alerts_list');
        let historyConf = localStorage.getItem('history');
        let filtersListConf = localStorage.getItem('filters_list');
        let pageDisplay = localStorage.getItem('page_display');
        let idsFilters = localStorage.getItem('ids_filters');
        let historyFilters = localStorage.getItem('history_filters');
        if (!duration) {
            duration = 24;
        }

        if (!rulesListConf) {
            rulesListConf = {
                pagination: {
                    page: 1,
                    perPage: 6,
                    perPageOptions: [6, 10, 15, 25]
                },
                sort: { id: 'created', asc: false },
                view_type: 'list'
            };
            localStorage.setItem('rules_list', JSON.stringify(rulesListConf));
        } else {
            rulesListConf = JSON.parse(rulesListConf);
            // Sanity checks for the object retrieved from local storage
            if (typeof rulesListConf.pagination === 'undefined') {
                rulesListConf.pagination = {};
            }
            if (typeof rulesListConf.pagination.page === 'undefined') {
                rulesListConf.pagination.page = 1;
            }
            if (typeof rulesListConf.pagination.perPage === 'undefined') {
                rulesListConf.pagination.perPage = 6;
            }
            if (typeof rulesListConf.pagination.perPageOptions === 'undefined') {
                rulesListConf.pagination.perPageOptions = [6, 10, 15, 25];
            }
        }

        if (!alertsListConf) {
            alertsListConf = {
                pagination: {
                    page: 1,
                    perPage: 20,
                    perPageOptions: [20, 50, 100]
                },
                sort: { id: 'timestamp', asc: false },
                view_type: 'list'
            };
            localStorage.setItem('alerts_list', JSON.stringify(alertsListConf));
        } else {
            alertsListConf = JSON.parse(alertsListConf);
        }

        if (!filtersListConf) {
            filtersListConf = {
                pagination: {
                    page: 1,
                    perPage: 20,
                    perPageOptions: [20, 50, 100]
                },
                sort: { id: 'timestamp', asc: false },
                view_type: 'list'
            };
            localStorage.setItem('filters_list', JSON.stringify(filtersListConf));
        } else {
            filtersListConf = JSON.parse(filtersListConf);
        }

        if (!historyConf) {
            historyConf = {
                pagination: {
                    page: 1,
                    perPage: 6,
                    perPageOptions: [6, 10, 15, 25, 50]
                },
                sort: { id: 'date', asc: false },
                view_type: 'list'
            };
            localStorage.setItem('history', JSON.stringify(historyConf));
        } else {
            historyConf = JSON.parse(historyConf);
        }

        if (!idsFilters) {
            idsFilters = [];
            localStorage.setItem('ids_filters', JSON.stringify(idsFilters));
        } else {
            idsFilters = JSON.parse(idsFilters);
        }

        if (!historyFilters) {
            historyFilters = [];
            localStorage.setItem('history_filters', JSON.stringify(historyFilters));
        } else {
            historyFilters = JSON.parse(historyFilters);
        }

        if (!pageDisplay) {
            pageDisplay = { page: PAGE_STATE.dashboards, item: undefined };
            localStorage.setItem('page_display', JSON.stringify(pageDisplay));
        } else {
            pageDisplay = JSON.parse(pageDisplay);
        }
        this.state = {
            sources: [],
            rulesets: [],
            duration,
            from_date: (Date.now() - (duration * 3600 * 1000)),
            interval,
            display: pageDisplay,
            rules_list: rulesListConf,
            alerts_list: alertsListConf,
            idsFilters,
            history: historyConf,
            historyFilters,
            filters_list: filtersListConf,
            hasConnectivity: true,
            connectionProblem: 'Scirius is not currently available.',
        };
        this.displaySource = this.displaySource.bind(this);
        this.displayRuleset = this.displayRuleset.bind(this);
        this.changeDuration = this.changeDuration.bind(this);
        this.changeRefreshInterval = this.changeRefreshInterval.bind(this);

        this.fromDate = this.fromDate.bind(this);

        this.onHomeClick = this.onHomeClick.bind(this);
        this.onDashboardClick = this.onDashboardClick.bind(this);
        this.onHistoryClick = this.onHistoryClick.bind(this);
        this.onFiltersClick = this.onFiltersClick.bind(this);
        this.onAlertsClick = this.onAlertsClick.bind(this);
        this.switchPage = this.switchPage.bind(this);
        this.needReload = this.needReload.bind(this);
        this.updateRuleListState = this.updateRuleListState.bind(this);
        this.updateAlertListState = this.updateAlertListState.bind(this);
        this.updateIDSFilterState = this.updateIDSFilterState.bind(this);
        this.updateHistoryListState = this.updateHistoryListState.bind(this);
        this.updateHistoryFilterState = this.updateHistoryFilterState.bind(this);
        this.updateFilterListState = this.updateFilterListState.bind(this);
    }

    getChildContext() {
        return { shortcuts: shortcutManager };
    }

    componentDidMount() {
        setInterval(this.get_scirius_status, 10000);
        axios.all([
            axios.get(config.API_URL + config.SOURCE_PATH),
            axios.get(config.API_URL + config.RULESET_PATH),
            axios.get(config.API_URL + config.SYSTEM_SETTINGS_PATH),
        ])
        .then(axios.spread((SrcRes, RulesetRes, systemSettings) => {
            this.setState({
                rulesets: RulesetRes.data.results,
                sources: SrcRes.data.results,
                systemSettings: systemSettings.data
            });
        }));

        if (this.state.interval) {
            this.timer = setInterval(this.needReload, this.state.interval * 1000);
        }
    }

    onHomeClick() {
        this.switchPage(PAGE_STATE.rules_list, undefined);
    }

    onAlertsClick() {
        this.switchPage(PAGE_STATE.alerts_list, undefined);
    }

    onDashboardClick() {
        this.switchPage(PAGE_STATE.dashboards, undefined);
    }

    onHistoryClick() {
        this.switchPage(PAGE_STATE.history, undefined);
    }

    onFiltersClick() {
        this.switchPage(PAGE_STATE.filters_list, undefined);
    }

    needReload() {
        this.setState({ from_date: (Date.now() - (this.state.duration * 3600 * 1000)) });
    }

    fromDate = (period) => {
        const duration = period * 3600 * 1000;
        return Date.now() - duration;
    }

    displayRuleset(ruleset) {
        this.switchPage(PAGE_STATE.ruleset, ruleset);
    }

    displaySource(source) {
        this.switchPage(PAGE_STATE.source, source);
    }

    changeDuration(period) {
        this.setState({ duration: period, from_date: this.fromDate(period) });
        localStorage.setItem('duration', period);
    }

    changeRefreshInterval(interval) {
        this.setState({ ...this.state, interval });
        localStorage.setItem('interval', interval);

        if (interval) {
            if (this.timer) {
                clearInterval(this.timer);
                this.timer = null;
            }
            this.timer = setInterval(this.needReload, interval * 1000);
        } else {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    switchPage(page, item) {
        if (!page) {
            return;
        }
        if (page === PAGE_STATE.rules_list && item !== undefined) {
            this.updateIDSFilterState([{
                label: `Signature ID: ${item}`,
                id: 'alert.signature_id',
                value: item,
                negated: false,
                query: 'filter'
            }]);
        }
        const pageDisplay = { page, item };
        this.setState({ display: pageDisplay });
        localStorage.setItem('page_display', JSON.stringify(pageDisplay));
    }

    updateRuleListState(rulesListState) {
        this.setState({ rules_list: rulesListState });
        localStorage.setItem('rules_list', JSON.stringify(rulesListState));
    }

    updateAlertListState(alertsListState) {
        this.setState({ alerts_list: alertsListState });
        localStorage.setItem('alerts_list', JSON.stringify(alertsListState));
    }

    updateFilterListState(filtersListState) {
        this.setState({ filters_list: filtersListState });
        localStorage.setItem('filters_list', JSON.stringify(filtersListState));
    }

    updateIDSFilterState(filters) {
        this.setState({ idsFilters: filters });
        localStorage.setItem('ids_filters', JSON.stringify(filters));
    }

    updateHistoryFilterState(filters) {
        this.setState({ historyFilters: filters });
        localStorage.setItem('history_filters', JSON.stringify(filters));
    }

    updateHistoryListState(historyState) {
        this.setState({ history: historyState });
        localStorage.setItem('history', JSON.stringify(historyState));
    }

    get_scirius_status = () => {
        axios({
            method: 'get',
            url: '/rules/info',
            timeout: 15000,
        }).then((data) => {
            if (!data) {
                if (this.state.hasConnectivity) {
                    this.setState({
                        ...this.state,
                        hasConnectivity: false
                    });
                }
            } else {
                if (data.data.status === 'green' && !this.state.hasConnectivity) {
                    this.setState({
                        ...this.state,
                        hasConnectivity: true
                    });
                }
                if (data.data.status !== 'green' && this.state.hasConnectivity) {
                    this.setState({
                        ...this.state,
                        hasConnectivity: false,
                        connectionProblem: 'Scirius does not feel comfortable',
                    });
                }
            }
        }).catch(() => {
            if (this.state.hasConnectivity) {
                this.setState({
                    ...this.state,
                    hasConnectivity: false,
                    connectionProblem: 'No connection with scirius. This pop-up will disappear if connection is restored.',
                });
            }
        });
    }

    render() {
        let displayedPage = null;
        switch (this.state.display.page) {
            case PAGE_STATE.rules_list:
            default:
                displayedPage = (<SignaturesPage
                    systemSettings={this.state.systemSettings}
                    rules_list={this.state.rules_list}
                    filters={this.state.idsFilters}
                    from_date={this.state.from_date}
                    SwitchPage={this.switchPage}
                    updateListState={this.updateRuleListState}
                    updateFilterState={this.updateIDSFilterState}
                />);
                break;
            case PAGE_STATE.source:
                displayedPage = <SourcePage systemSettings={this.state.systemSettings} source={this.state.display.item} from_date={this.state.from_date} />;
                break;
            case PAGE_STATE.ruleset:
                displayedPage = <RulesetPage systemSettings={this.state.systemSettings} ruleset={this.state.display.item} from_date={this.state.from_date} />;
                break;
            case PAGE_STATE.dashboards:
                // FIXME remove or change updateRuleListState
                displayedPage = (<HuntDashboard
                    systemSettings={this.state.systemSettings}
                    config={this.state.rules_list}
                    filters={this.state.idsFilters}
                    from_date={this.state.from_date}
                    SwitchPage={this.switchPage}
                    updateListState={this.updateRuleListState}
                    updateFilterState={this.updateIDSFilterState}
                    needReload={this.needReload}
                />);
                break;
            case PAGE_STATE.history:
                displayedPage = (<HistoryPage
                    systemSettings={this.state.systemSettings}
                    config={this.state.history}
                    filters={this.state.historyFilters}
                    from_date={this.state.from_date}
                    updateListState={this.updateHistoryListState}
                    switchPage={this.switchPage}
                    updateFilterState={this.updateHistoryFilterState}
                />);
                break;
            case PAGE_STATE.alerts_list:
                displayedPage = (<AlertsList
                    systemSettings={this.state.systemSettings}
                    config={this.state.alerts_list}
                    filters={this.state.idsFilters}
                    from_date={this.state.from_date}
                    updateListState={this.updateAlertListState}
                    switchPage={this.switchPage}
                    updateFilterState={this.updateIDSFilterState}
                />);
                break;
            case PAGE_STATE.filters_list:
                displayedPage = (<FiltersList
                    systemSettings={this.state.systemSettings}
                    config={this.state.filters_list}
                    filters={this.state.filters_filters}
                    from_date={this.state.from_date}
                    updateListState={this.updateFilterListState}
                    switchPage={this.switchPage}
                    updateFilterState={this.updateFiltersFilterState}
                />);
                break;
        }
        return (
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
                    <VerticalNav.Masthead title="Scirius">
                        <VerticalNav.Brand titleImg={sciriusLogo} />

                        <VerticalNav.IconBar>
                            <UserNavInfo
                                systemSettings={this.state.systemSettings}
                                ChangeDuration={this.changeDuration}
                                ChangeRefreshInterval={this.changeRefreshInterval}
                                interval={this.state.interval}
                                period={this.state.duration}
                                needReload={this.needReload}
                            />
                        </VerticalNav.IconBar>


                    </VerticalNav.Masthead>
                    <VerticalNav.Item
                        title="Dashboard"
                        iconClass="fa fa-tachometer"
                        initialActive={this.state.display.page === PAGE_STATE.dashboards}
                        onClick={this.onDashboardClick}
                        className={null}
                    />
                    <VerticalNav.Item
                        title="Signatures"
                        iconClass="glyphicon glyphicon-eye-open"
                        initialActive={[PAGE_STATE.rules_list, PAGE_STATE.rule, PAGE_STATE.source, PAGE_STATE.ruleset].indexOf(this.state.display.page) >= 0}
                        onClick={this.onHomeClick}
                        className={null}
                    />
                    <VerticalNav.Item
                        title="Alerts"
                        iconClass="pficon pficon-security"
                        initialActive={this.state.display.page === PAGE_STATE.alerts_list}
                        onClick={this.onAlertsClick}
                    />
                    { (process.env.REACT_APP_HAS_ACTION === '1' || process.env.NODE_ENV === 'development') && <VerticalNav.Item
                        title="Actions"
                        iconClass="glyphicon glyphicon-filter"
                        initialActive={this.state.display.page === PAGE_STATE.filters_list}
                        onClick={this.onFiltersClick}
                    />}
                    <VerticalNav.Item
                        title="History"
                        iconClass="glyphicon glyphicon-list"
                        initialActive={this.state.display.page === PAGE_STATE.history}
                        onClick={this.onHistoryClick}
                    />

                </VerticalNav>
                <div className="container-fluid container-pf-nav-pf-vertical nav-pf-persistent-secondary">
                    <div className="row row-cards-pf">
                        <div className="col-xs-12 col-sm-12 col-md-12" id="app-content">
                            {displayedPage}
                        </div>
                    </div>
                </div>

                <Modal show={!this.state.hasConnectivity}>
                    <Modal.Header>
                        <Modal.Title>Scirius is down</Modal.Title>
                    </Modal.Header>
                    <Modal.Body>
                        <div className="modal-body text-danger">{this.state.connectionProblem}</div>
                    </Modal.Body>
                </Modal>
            </div>
        );
    }
}

export default HuntApp;

HuntApp.childContextTypes = {
    shortcuts: PropTypes.object.isRequired
};
