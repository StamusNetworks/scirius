/* eslint-disable camelcase,react/sort-comp */
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
import { VerticalNav, Modal, VerticalNavItem } from 'patternfly-react';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';
import axios from 'axios';
import VerticalNavItems from 'hunt_common/components/VerticalNavItems';
import DisplayPage from 'hunt_common/components/DisplayPage';
import { PAGE_STATE } from 'hunt_common/constants';
import * as config from 'hunt_common/config/Api';
import UserNavInfo from 'hunt_common/containers/UserNavInfo';
import EmitEvent from '../../helpers/EmitEvent';
import '../../pygments.css';
import '../../css/App.css';
import sciriusLogo from '../../img/stamus.png';
import keymap from '../../Keymap';
import ErrorHandler from '../../components/Error';
import storage from '../../helpers/storage';

const shortcutManager = new ShortcutManager(keymap);

export default class App extends Component {
    constructor(props) {
        super(props);
        this.timer = null;
        const interval = storage.getItem('interval');
        let rulesListConf = storage.getItem('rules_list');
        let alertsListConf = storage.getItem('alerts_list');
        let historyConf = storage.getItem('history');
        let filtersListConf = storage.getItem('filters_list');
        let pageDisplay = storage.getItem('page_display');
        let historyFilters = storage.getItem('history_filters');

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
            storage.setItem('rules_list', JSON.stringify(rulesListConf));
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
            storage.setItem('alerts_list', JSON.stringify(alertsListConf));
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
            storage.setItem('filters_list', JSON.stringify(filtersListConf));
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
            storage.setItem('history', JSON.stringify(historyConf));
        } else {
            historyConf = JSON.parse(historyConf);
        }

        if (!historyFilters) {
            historyFilters = [];
            storage.setItem('history_filters', JSON.stringify(historyFilters));
        } else {
            historyFilters = JSON.parse(historyFilters);
        }

        if (!pageDisplay) {
            pageDisplay = { page: PAGE_STATE.dashboards, item: undefined };
            storage.setItem('page_display', JSON.stringify(pageDisplay));
        } else {
            pageDisplay = JSON.parse(pageDisplay);
        }
        this.state = {
            sources: [],
            rulesets: [],
            interval,
            display: pageDisplay,
            rules_list: rulesListConf,
            alerts_list: alertsListConf,
            history: historyConf,
            historyFilters,
            filters_list: filtersListConf,
            hasConnectivity: true,
            connectionProblem: 'Scirius is not currently available.',
        };
        this.changeRefreshInterval = this.changeRefreshInterval.bind(this);
        this.switchPage = this.switchPage.bind(this);
        this.needReload = this.needReload.bind(this);
        this.updateRuleListState = this.updateRuleListState.bind(this);
        this.updateAlertListState = this.updateAlertListState.bind(this);
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

    needReload() {
        this.props.reload();
    }

    fromDate = (period) => {
        const duration = period * 3600 * 1000;
        return Date.now() - duration;
    }

    changeRefreshInterval(interval) {
        this.setState({ ...this.state, interval });
        storage.setItem('interval', interval);

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
        const pageDisplay = { page, item };
        this.setState({ display: pageDisplay });
        storage.setItem('page_display', JSON.stringify(pageDisplay));
    }

    updateRuleListState(rulesListState) {
        this.setState({ rules_list: rulesListState });
        storage.setItem('rules_list', JSON.stringify(rulesListState));
    }

    updateAlertListState(alertsListState) {
        this.setState({ alerts_list: alertsListState });
        storage.setItem('alerts_list', JSON.stringify(alertsListState));
    }

    updateFilterListState(filtersListState) {
        this.setState({ filters_list: filtersListState });
        storage.setItem('filters_list', JSON.stringify(filtersListState));
    }

    updateHistoryFilterState(filters) {
        this.setState({ historyFilters: filters });
        storage.setItem('history_filters', JSON.stringify(filters));
    }

    updateHistoryListState(historyState) {
        this.setState({ history: historyState });
        storage.setItem('history', JSON.stringify(historyState));
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

    adjustDashboardWidth = () => {
        setTimeout(() => {
            EmitEvent('resize');
            EmitEvent('resize');
        }, 150);
    };

    render() {
        return (
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges onCollapse={this.adjustDashboardWidth} onExpand={this.adjustDashboardWidth}>
                    <VerticalNav.Masthead>
                        <VerticalNav.Brand>
                            <img src={sciriusLogo} height={32} width={116} style={{ marginTop: 7, marginBottom: -7, marginLeft: 20, display: 'block', float: 'left' }} alt="logo" />
                            <div style={{ fontSize: '20px', float: 'left', paddingLeft: '40px', paddingTop: '11px', fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'" }}>
                                {process.env.REACT_APP_HAS_TAG === '1' ? <React.Fragment>Scirius Enriched Hunting</React.Fragment> : <React.Fragment>Scirius Threat Hunting</React.Fragment>}
                            </div>
                        </VerticalNav.Brand>

                        <VerticalNav.IconBar>
                            <ErrorHandler>
                                <UserNavInfo
                                    systemSettings={this.state.systemSettings}
                                    ChangeRefreshInterval={this.changeRefreshInterval}
                                    interval={this.state.interval}
                                    switchPage={this.switchPage}
                                    needReload={this.needReload}
                                    duration={this.props.duration}
                                />
                            </ErrorHandler>
                        </VerticalNav.IconBar>

                    </VerticalNav.Masthead>
                    {VerticalNavItems.map((v) => <VerticalNavItem
                        title={v.title}
                        iconClass={v.iconClass}
                        key={Math.random()}
                        onClick={() => this.switchPage(v.def, undefined)}
                        active={this.state.display.page === v.def}
                    />)}
                </VerticalNav>
                <div className="container-fluid container-pf-nav-pf-vertical nav-pf-persistent-secondary">
                    <div className="row row-cards-pf">
                        <div className="col-xs-12 col-sm-12 col-md-12 no-col-gutter-right" id="app-content">
                            {/* {displayedPage} */}
                            <ErrorHandler>
                                <DisplayPage
                                    page={this.state.display.page}
                                    systemSettings={this.state.systemSettings}
                                    rules_list={this.state.rules_list}
                                    idsFilters={this.state.idsFilters}
                                    switchPage={this.switchPage}
                                    updateRuleListState={this.updateRuleListState}
                                    item={this.state.display.item}
                                    needReload={this.needReload}
                                    history_list={this.state.history}
                                    historyFilters={this.state.historyFilters}
                                    updateHistoryListState={this.updateHistoryListState}
                                    updateHistoryFilterState={this.updateHistoryFilterState}
                                    alerts_list={this.state.alerts_list}
                                    updateAlertListState={this.updateAlertListState}
                                    filters_list={this.state.filters_list}
                                    filters_filters={this.state.filters_filters}
                                    updateFilterListState={this.updateFilterListState}
                                    updateFiltersFilterState={this.updateFiltersFilterState}
                                    updateHostListState={this.updateHostListState}
                                    hosts_list={this.state.hosts_list}
                                />
                            </ErrorHandler>
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

App.childContextTypes = {
    shortcuts: PropTypes.object.isRequired
};

App.propTypes = {
    reload: PropTypes.func.isRequired,
    duration: PropTypes.any,
}
