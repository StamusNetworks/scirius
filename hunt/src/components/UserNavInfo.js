import React, { Component } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { PAGE_STATE } from 'hunt_common/constants';
import { Dropdown, Icon, MenuItem, ApplicationLauncher, ApplicationLauncherItem, AboutModal, Modal, Form, Button } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import HuntNotificationArea from '../HuntNotificationArea';
import ExternalLink from './ExternalLink';
import OutsideAlerter from './OutsideAlerter';
import sciriusLogo from '../img/scirius-by-stamus.svg';
import ErrorHandler from './Error';

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

export default class UserNavInfo extends Component {
    constructor(props) {
        super(props);
        this.state = {
            showModal: false,
            showUpdateModal: false,
            showNotifications: false,
            user: undefined,
            isShown: false,
            context: undefined
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

        axios.get(`${config.API_URL}${config.SCIRIUS_CONTEXT}`)
        .then((context) => {
            this.setState({ context: context.data });
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
        const { title, version } = (this.state.context !== undefined) ? this.state.context : { title: '', version: '' };

        return (
            <React.Fragment>

                <li className="dropdown">
                    <div tabIndex={0} data-toggle="tooltip" title="Update threat detection" onClick={this.showUpdateThreatDetection} role="button" className="nav-item-iconic">
                        <Icon type="fa" name="upload" />
                    </div>
                </li>

                <li className="dropdown">
                    <div tabIndex={0} data-toggle="tooltip" title="History" onClick={() => this.props.switchPage(PAGE_STATE.history, undefined)} role="button" className="nav-item-iconic">
                        <i className="glyphicon glyphicon-list" aria-hidden="true"></i>
                        <span> History</span>
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

                {this.state.showNotifications && <ErrorHandler><HuntNotificationArea /></ErrorHandler>}
                <ErrorHandler>
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
                </ErrorHandler>
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
                    productTitle={title}
                    logo={sciriusLogo}
                    altLogo="SEE Logo"
                    trademarkText="Copyright 2014-2018, Stamus Networks"
                >
                    <AboutModal.Versions>
                        <AboutModal.VersionItem label="Version" versionText={version} />
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
    switchPage: PropTypes.any,
    ChangeDuration: PropTypes.any,
};
