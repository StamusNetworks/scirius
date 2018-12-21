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
import { VerticalNav, Dropdown, Icon, MenuItem, ApplicationLauncher, ApplicationLauncherItem, AboutModal, Modal, Form, Button } from 'patternfly-react';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';
import axios from 'axios';
import { HuntDashboard } from './Dashboard';
import HuntNotificationArea from './HuntNotificationArea';
import { HistoryPage } from './History';
import { PAGE_STATE } from './constants';
import { RulesList } from './RulesList';
import { AlertsList } from './AlertsList';
import { FiltersList } from './Filters';
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
                displayedPage = (<RulesList
                    systemSettings={this.state.systemSettings}
                    config={this.state.rules_list}
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


const USER_PERIODS = {
    1: '1h',
    6: '6h',
    24: '24h',
    48: '2d',
    168: '7d',
    720: '30d'
};


const REFRESH_INTERVAL = {
    '': 'Off',
    10: '10s',
    30: '30s',
    60: '1m',
    120: '2m',
    300: '5m',
    900: '15m',
    1800: '30m',
    3600: '1h'
};


// eslint-disable-next-line react/no-multi-comp
class ExternalLink extends Component {
    constructor(props) {
        super(props);
        this.state = {
            onclick: props.onClick,
            icon: props.icon,
            title: props.title,
            tooltip: props.tooltip
        };
    }

    render() {
        return (
            <li className="applauncher-pf-item" role="presentation">
                <a className="applauncher-pf-link" onClick={() => this.state.onclick} role="menuitem" data-toggle="tooltip" title={this.state.tooltip} style={{ cursor: 'pointer' }} tabIndex={0}>
                    <i className={this.state.icon} aria-hidden="true" />
                    <span className="applauncher-pf-link-title">{this.state.title}</span>
                </a>
            </li>
        );
    }
}
ExternalLink.propTypes = {
    onClick: PropTypes.any,
    icon: PropTypes.any,
    title: PropTypes.any,
    tooltip: PropTypes.any,
};

// eslint-disable-next-line react/no-multi-comp
class OutsideAlerter extends Component {
    constructor(props) {
        super(props);

        this.setWrapperRef = this.setWrapperRef.bind(this);
        this.handleClickOutside = this.handleClickOutside.bind(this);
    }

    componentDidMount() {
        document.addEventListener('mousedown', this.handleClickOutside);
    }

    componentWillUnmount() {
        document.removeEventListener('mousedown', this.handleClickOutside);
    }

    setWrapperRef(node) {
        this.wrapperRef = node;
    }

    handleClickOutside(event) {
        if (this.wrapperRef && !this.wrapperRef.contains(event.target)) {
            this.props.hide();
        }
    }

    render() {
        return <span ref={this.setWrapperRef}>{this.props.children}</span>;
    }
}
OutsideAlerter.propTypes = {
    hide: PropTypes.func,
    children: PropTypes.element.isRequired,
};


// eslint-disable-next-line react/no-multi-comp
class UserNavInfo extends Component {
    constructor(props) {
        super(props);
        this.state = {
            showModal: false,
            showUpdateModal: false,
            showNotifications: false,
            user: undefined,
            isShown: false,
        };
        this.AboutClick = this.AboutClick.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.toggleNotifications = this.toggleNotifications.bind(this);
        this.toggleiSshown = this.toggleiSshown.bind(this);
        this.isShownFalse = this.isShownFalse.bind(this);
        this.toggleHunt = this.toggleHunt.bind(this);
        this.toggleHome = this.toggleHome.bind(this);
        this.toggleDashboards = this.toggleDashboards.bind(this);
        this.toggleEvebox = this.toggleEvebox.bind(this);
        this.showUpdateThreatDetection = this.showUpdateThreatDetection.bind(this);
        this.closeShowUpdate = this.closeShowUpdate.bind(this);
        this.submitUpdate = this.submitUpdate.bind(this);
    }

    componentDidMount() {
        axios.get(`${config.API_URL}${config.USER_PATH}current_user/`)
        .then((currentUser) => {
            this.setState({ user: currentUser.data });
        });
    }

    AboutClick() {
        this.setState({ showModal: true });
    }

    closeModal() {
        this.setState({ showModal: false });
    }

    toggleNotifications() {
        this.setState({ showNotifications: !this.state.showNotifications });
    }

    toggleiSshown() {
        this.setState({ isShown: !this.state.isShown });
    }

    isShownFalse() {
        this.setState({ isShown: false });
    }

    toggleHunt() {
        this.setState({ isShown: !this.state.isShown });
        window.open('/rules/hunt', '_self');
    }

    toggleHome() {
        this.setState({ isShown: !this.state.isShown });
        window.open('/rules', '_self');
    }

    toggleDashboards() {
        this.setState({ isShown: !this.state.isShown });
        window.open(this.props.systemSettings.kibana_url, '_self');
    }

    toggleEvebox() {
        this.setState({ isShown: !this.state.isShown });
        window.open(this.props.systemSettings.evebox_url, '_self');
    }

    showUpdateThreatDetection() {
        this.setState({ showUpdateModal: !this.state.showUpdateModal });
    }

    closeShowUpdate() {
        this.setState({ showUpdateModal: false });
    }

    submitUpdate() {
        let url = config.UPDATE_PUSH_RULESET_PATH;
        if (process.env.REACT_APP_HAS_TAG === '1') {
            url = 'rest/appliances/appliance/update_push_all/';
        }
        axios.post(config.API_URL + url, {});
        this.setState({ showUpdateModal: false });
    }

    render() {
        let user = ' ...';
        if (this.state.user !== undefined) {
            user = this.state.user.username;
        }
        return (
            <React.Fragment>

                <li className="dropdown">
                    <div tabIndex={0} data-toggle="tooltip" title="Update threat detection" onClick={this.showUpdateThreatDetection} role="button" className="nav-item-iconic">
                        <Icon type="fa" name="upload" />
                    </div>
                </li>

                <Dropdown componentClass="li" id="timeinterval">
                    <Dropdown.Toggle useAnchor className="nav-item-iconic">
                        <Icon type="fa" name="clock-o" /> Refresh Interval {REFRESH_INTERVAL[this.props.interval]}
                    </Dropdown.Toggle>
                    <Dropdown.Menu>
                        {Object.keys(REFRESH_INTERVAL).map((interval) => (
                            <MenuItem key={interval} onClick={() => this.props.ChangeRefreshInterval(interval)}>{REFRESH_INTERVAL[interval]}</MenuItem>
                        ), this)}
                    </Dropdown.Menu>
                </Dropdown>

                <li className="dropdown">
                    <a tabIndex={0} id="refreshtime" role="button" className="nav-item-iconic" onClick={this.props.needReload}>
                        <Icon type="fa" name="refresh" />
                    </a>
                </li>

                <Dropdown componentClass="li" id="time">
                    <Dropdown.Toggle useAnchor className="nav-item-iconic">
                        <Icon type="fa" name="clock-o" /> Last {USER_PERIODS[this.props.period]}
                    </Dropdown.Toggle>
                    <Dropdown.Menu>
                        {Object.keys(USER_PERIODS).map((period) => (<MenuItem key={period} onClick={() => this.props.ChangeDuration(period)}>Last {USER_PERIODS[period]}</MenuItem>), this)}
                    </Dropdown.Menu>
                </Dropdown>

                {this.state.showNotifications && <HuntNotificationArea />}
                <OutsideAlerter hide={this.isShownFalse}>
                    <ApplicationLauncher grid open={this.state.isShown} toggleLauncher={this.toggleiSshown}>
                        <ApplicationLauncherItem
                            icon="rebalance"
                            title="Hunt"
                            tooltip="Threat Hunting"
                            onClick={this.toggleHunt}
                        />

                        <ApplicationLauncherItem
                            icon="server"
                            title="Administration"
                            tooltip="Appliances Management"
                            onClick={this.toggleHome}
                        />

                        {this.props.systemSettings && this.props.systemSettings.kibana && <ExternalLink
                            onClick={this.toggleDashboards}
                            icon="glyphicon glyphicon-stats"
                            title="Dashboards"
                            tooltip="Kibana dashboards for ES"
                        />}

                        {this.props.systemSettings && this.props.systemSettings.evebox && <ExternalLink
                            onClick={this.toggleEvebox}
                            icon="glyphicon glyphicon-th-list"
                            title="Events viewer"
                            tooltip="Evebox alert and event management tool"
                        />}

                    </ApplicationLauncher>
                </OutsideAlerter>
                <Dropdown componentClass="li" id="help">
                    <Dropdown.Toggle useAnchor className="nav-item-iconic">
                        <Icon type="pf" name="help" />
                    </Dropdown.Toggle>
                    <Dropdown.Menu>
                        <MenuItem href="/static/doc/hunt.html" target="_blank"><span className="glyphicon glyphicon-book" /> Help</MenuItem>
                        <MenuItem onClick={this.AboutClick}><span className="glyphicon glyphicon-question-sign" /> About</MenuItem>
                    </Dropdown.Menu>
                </Dropdown>

                <Dropdown componentClass="li" id="user">
                    <Dropdown.Toggle useAnchor className="nav-item-iconic">
                        <Icon type="pf" name="user" /> {user}
                    </Dropdown.Toggle>
                    <Dropdown.Menu>
                        <MenuItem href="/accounts/edit"><span className="glyphicon glyphicon-cog" /> Account settings</MenuItem>
                        <MenuItem href="/accounts/logout"><span className="glyphicon glyphicon-log-out" /> Logout</MenuItem>
                    </Dropdown.Menu>
                </Dropdown>

                <Modal show={this.state.showUpdateModal}>
                    <Modal.Header>
                        <button
                            className="close"
                            onClick={this.closeShowUpdate}
                            aria-hidden="true"
                            aria-label="Close"
                        >
                            <Icon type="pf" name="close" />
                        </button>

                        <Modal.Title> Update threat detection </Modal.Title>

                    </Modal.Header>

                    <Modal.Body>
                        {process.env.REACT_APP_HAS_TAG && <Form horizontal>
                            You are going to update threat detection (push ruleset and update post processing).
                            Do you want to continue ?
                        </Form>}
                        {!process.env.REACT_APP_HAS_TAG && <Form horizontal>
                            You are going to update threat detection (update/push ruleset).
                            Do you want to continue ?
                        </Form>}
                    </Modal.Body>

                    <Modal.Footer>
                        <Button
                            bsStyle="default"
                            className="btn-cancel"
                            onClick={this.closeShowUpdate}
                        >
                            Cancel
                        </Button>

                        <Button bsStyle="primary" onClick={this.submitUpdate}>
                            Submit
                        </Button>

                    </Modal.Footer>
                </Modal>

                <AboutModal
                    show={this.state.showModal}
                    onHide={this.closeModal}
                    productTitle="Scirius Community Edition"
                    logo={sciriusLogo}
                    altLogo="SEE Logo"
                    trademarkText="Copyright 2014-2018, Stamus Networks"
                >
                    <AboutModal.Versions>
                        <AboutModal.VersionItem label="Version" versionText="3.1.0" />
                    </AboutModal.Versions>
                </AboutModal>
            </React.Fragment>
        );
    }
}
UserNavInfo.propTypes = {
    interval: PropTypes.any,
    systemSettings: PropTypes.any,
    needReload: PropTypes.any,
    ChangeRefreshInterval: PropTypes.any,
    period: PropTypes.any,
    ChangeDuration: PropTypes.any,
};

// eslint-disable-next-line react/prefer-stateless-function,react/no-multi-comp
class SourcePage extends Component {
    render() {
        const { source } = this.props;
        return (
            <h1>{source.name}</h1>
        );
    }
}
SourcePage.propTypes = {
    source: PropTypes.any
};

// eslint-disable-next-line react/prefer-stateless-function,react/no-multi-comp
class RulesetPage extends Component {
    render() {
        const { ruleset } = this.props;
        return (
            <h1>{ruleset.name}</h1>
        );
    }
}
RulesetPage.propTypes = {
    ruleset: PropTypes.any
};

export default HuntApp;

HuntApp.childContextTypes = {
    shortcuts: PropTypes.object.isRequired
};
