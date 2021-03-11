import React, { Component } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { PAGE_STATE, APP_NAME_SHORT } from 'hunt_common/constants';
import { Dropdown, Icon, MenuItem, ApplicationLauncher, AboutModal, Modal, Form, Button } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import { compose } from 'redux';
import FilterSets from '../../../components/FilterSets';
import OutsideAlerter from '../../../components/OutsideAlerter';
import sciriusLogo from '../../../img/stamus_logo.png';
import ErrorHandler from '../../../components/Error';
import TimeSpanItem from '../../../components/TimeSpanItem';
import { withPermissions } from '../../../containers/App/stores/withPermissions';

const REFRESH_INTERVAL = {
  '': 'Off',
  10: '10s',
  30: '30s',
  60: '1m',
  120: '2m',
  300: '5m',
  900: '15m',
  1800: '30m',
  3600: '1h',
};

class UserNavInfo extends Component {
  constructor(props) {
    super(props);
    this.state = {
      showModal: false,
      showUpdateModal: false,
      showNotifications: false,
      isShown: false,
      context: undefined,
    };
    this.AboutClick = this.AboutClick.bind(this);
    this.closeModal = this.closeModal.bind(this);
    this.toggleNotifications = this.toggleNotifications.bind(this);
    this.toggleiSshown = this.toggleiSshown.bind(this);
    this.isShownFalse = this.isShownFalse.bind(this);
    this.showUpdateThreatDetection = this.showUpdateThreatDetection.bind(this);
    this.closeShowUpdate = this.closeShowUpdate.bind(this);
    this.submitUpdate = this.submitUpdate.bind(this);

    this.toggleHuntFilterSetsModal = this.toggleHuntFilterSetsModal.bind(this);
    this.closeHuntFilterSetsModal = this.closeHuntFilterSetsModal.bind(this);
  }

  componentDidMount() {
    axios.get(`${config.API_URL}${config.SCIRIUS_CONTEXT}`).then((context) => {
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
    if (this.state.isShown) {
      this.setState({ isShown: false });
    }
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

  closeHuntFilterSetsModal() {
    if (this.state.showNotifications) {
      this.setState({ showNotifications: false });
    }
  }

  toggleHuntFilterSetsModal() {
    this.setState((prevState) => ({
      showNotifications: !prevState.showNotifications,
    }));
  }

  getManagement() {
    if (
      this.props.systemSettings &&
      ((this.props.systemSettings.license && this.props.systemSettings.license.mngt) || !this.props.systemSettings.license)
    )
      return (
        <li className="applauncher-pf-item" role="presentation">
          <a
            className="applauncher-pf-link"
            href="/rules"
            role="menuitem"
            data-toggle="tooltip"
            title="Appliances Management"
            style={{ cursor: 'pointer' }}
          >
            <img src="/static/rules/Stamus_SPM_icon.png" height="40" width="40" alt="Management" />
            <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
              Management
            </span>
          </a>
        </li>
      );

    return (
      <li className="applauncher-pf-item">
        <div className="applauncher-pf-link">
          <img src="/static/rules/Stamus_SPM_icon.png" height="40" width="40" style={{ filter: 'opacity(.2)' }} />
          <span className="applauncher-pf-link-title" style={{ fontSize: '12px', color: 'rgba(0,0,0,.2)', lineHeight: '1.5715' }}>
            Management
          </span>
        </div>
      </li>
    );
  }

  getThreatRadar() {
    if (
      process.env.REACT_APP_HAS_TAG === '1' &&
      this.props.systemSettings &&
      this.props.systemSettings.license &&
      this.props.systemSettings.license.nta &&
      this.props.user.permissions.includes('rules.events_view')
    )
      return (
        <li className="applauncher-pf-item" role="presentation">
          <a
            className="applauncher-pf-link"
            href="/appliances/str"
            role="menuitem"
            data-toggle="tooltip"
            title="Threat Radar"
            style={{ cursor: 'pointer' }}
          >
            <img src="/static/rules/Stamus_STR_icon.png" height="40" width="40" alt="STR" />
            <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
              Threat Radar
            </span>
          </a>
        </li>
      );
    return true;
  }

  render() {
    const user = this.props.user.username.length === 0 ? ' ...' : this.props.user.username;
    const { title, version } = this.state.context !== undefined ? this.state.context : { title: '', version: '' };

    return (
      <React.Fragment>
        <li>
          <div
            tabIndex={0}
            data-toggle="tooltip"
            title="Update threat detection"
            onClick={this.showUpdateThreatDetection}
            role="button"
            className="nav-item-iconic"
          >
            <Icon type="fa" name="upload" />
          </div>
        </li>

        <li>
          <div
            tabIndex={0}
            data-toggle="tooltip"
            title="History"
            onClick={() => this.props.switchPage(PAGE_STATE.history, undefined)}
            role="button"
            className="nav-item-iconic"
            style={{ paddingTop: '23px' }}
          >
            <i className="glyphicon glyphicon-list" aria-hidden="true" />
            <span> History</span>
          </div>
        </li>

        <li>
          <div
            tabIndex={0}
            data-toggle="tooltip"
            title="Filter Sets"
            onClick={(e) => {
              e.preventDefault();
              this.toggleHuntFilterSetsModal();
            }}
            role="button"
            className="nav-item-iconic"
            style={{ paddingTop: '23px', cursor: 'pointer' }}
          >
            <i className="glyphicon glyphicon-filter" aria-hidden="true" />
            <span> Filter Sets</span>
          </div>
        </li>

        {parseInt(this.props.duration, 10) > 0 && (
          <Dropdown componentClass="li" id="timeinterval">
            <Dropdown.Toggle useAnchor className="nav-item-iconic">
              <Icon type="fa" name="clock-o" /> Refresh Interval {REFRESH_INTERVAL[this.props.interval]}
            </Dropdown.Toggle>
            <Dropdown.Menu>
              {Object.keys(REFRESH_INTERVAL).map(
                (interval) => (
                  <MenuItem key={interval} onClick={() => this.props.ChangeRefreshInterval(interval)}>
                    {REFRESH_INTERVAL[interval]}
                  </MenuItem>
                ),
                this,
              )}
            </Dropdown.Menu>
          </Dropdown>
        )}

        <li>
          <a tabIndex={0} id="refreshtime" role="button" className="nav-item-iconic" onClick={this.props.needReload}>
            <Icon type="fa" name="refresh" />
          </a>
        </li>

        {this.props.children}
        <TimeSpanItem />
        {this.state.showNotifications && (
          <ErrorHandler>
            <FilterSets switchPage={this.props.switchPage} close={this.closeHuntFilterSetsModal} reload={this.props.needReload} />
          </ErrorHandler>
        )}

        <ErrorHandler>
          <OutsideAlerter hide={this.isShownFalse}>
            <ApplicationLauncher grid open={this.state.isShown} toggleLauncher={this.toggleiSshown}>
              <div style={{ padding: '2px 6px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '20px repeat(3, 100px)' }}>
                  <div style={{ position: 'relative' }}>
                    <div
                      style={{
                        position: 'absolute',
                        top: '-36px',
                        left: '-81px',
                        width: '100px',
                        transformOrigin: '100% 100%',
                        transform: 'rotate(-90deg)',
                        color: 'rgba(0, 0, 0, .5)',
                        fontWeight: '600',
                        fontSize: '10px',
                      }}
                    >
                      {APP_NAME_SHORT} APPS
                    </div>
                  </div>
                  <li className="applauncher-pf-item" role="presentation">
                    <a
                      className="applauncher-pf-link"
                      href="/rules/hunt"
                      role="menuitem"
                      data-toggle="tooltip"
                      title="Threat Hunting"
                      style={{ cursor: 'pointer' }}
                    >
                      <img src="/static/rules/Stamus_SEH_icon.png" height="40" width="40" alt="Hunt" />
                      <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
                        Hunting
                      </span>
                    </a>
                  </li>
                  {this.getManagement()}
                  {this.getThreatRadar()}
                </div>
                {this.props.systemSettings &&
                  (this.props.systemSettings.kibana || this.props.systemSettings.evebox || this.props.systemSettings.cyberchef) && (
                    <hr style={{ border: '0.5px solid rgba(0,0,0,.1)', background: 'rgba(0,0,0,.1)', margin: '7px 0' }} />
                  )}
                <div style={{ display: 'grid', gridTemplateColumns: '20px repeat(3, 100px)' }}>
                  {this.props.systemSettings &&
                    (this.props.systemSettings.kibana || this.props.systemSettings.evebox || this.props.systemSettings.cyberchef) && (
                      <div style={{ position: 'relative' }}>
                        <div
                          style={{
                            position: 'absolute',
                            top: '-32px',
                            left: '-81px',
                            width: '100px',
                            transformOrigin: '100% 100%',
                            transform: 'rotate(-90deg)',
                            color: 'rgba(0, 0, 0, .5)',
                            fontWeight: '600',
                            fontSize: '10px',
                          }}
                        >
                          EXTERNAL APPS
                        </div>
                      </div>
                    )}
                  {this.props.systemSettings && this.props.systemSettings.kibana && this.props.user.permissions.includes('rules.events_kibana') && (
                    <li className="applauncher-pf-item" role="presentation">
                      <a
                        className="applauncher-pf-link"
                        href={this.props.systemSettings.kibana_url}
                        role="menuitem"
                        data-toggle="tooltip"
                        title="Kibana dashboards for ES"
                        style={{ color: 'inherit' }}
                        target="_blank"
                      >
                        <i style={{ fontSize: '2.5em', height: '40px', width: '40px' }} className="glyphicon glyphicon-stats" aria-hidden="true"></i>
                        <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
                          {'Kibana'} <i className="glyphicon glyphicon-new-window" />
                        </span>
                      </a>
                    </li>
                  )}

                  {this.props.systemSettings && this.props.systemSettings.evebox && this.props.user.permissions.includes('rules.events_evebox') && (
                    <li className="applauncher-pf-item" role="presentation">
                      <a
                        className="applauncher-pf-link"
                        href={this.props.systemSettings.evebox_url}
                        role="menuitem"
                        data-toggle="tooltip"
                        title="Evebox alert and event management tool"
                        style={{ color: 'inherit' }}
                        target="_blank"
                      >
                        <i
                          style={{ fontSize: '2.5em', height: '40px', width: '40px' }}
                          className="glyphicon glyphicon-th-list"
                          aria-hidden="true"
                        ></i>
                        <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
                          {'Evebox'} <i className="glyphicon glyphicon-new-window" />
                        </span>
                      </a>
                    </li>
                  )}

                  {this.props.systemSettings && this.props.systemSettings.cyberchef && (
                    <li className="applauncher-pf-item" role="presentation">
                      <a
                        className="applauncher-pf-link"
                        href={this.props.systemSettings.cyberchef_url}
                        role="menuitem"
                        data-toggle="tooltip"
                        title="Cyberchef data processing tool"
                        style={{ color: 'inherit' }}
                        target="_blank"
                      >
                        <i
                          style={{ fontSize: '2.5em', height: '40px', width: '40px' }}
                          className="glyphicon glyphicon-cutlery"
                          aria-hidden="true"
                        ></i>
                        <span className="applauncher-pf-link-title" style={{ lineHeight: '1.5715' }}>
                          {'Cyberchef'} <i className="glyphicon glyphicon-new-window" />
                        </span>
                      </a>
                    </li>
                  )}
                </div>
              </div>
            </ApplicationLauncher>
          </OutsideAlerter>
        </ErrorHandler>
        <Dropdown componentClass="li" id="help">
          <Dropdown.Toggle useAnchor className="nav-item-iconic">
            <Icon type="pf" name="help" />
          </Dropdown.Toggle>
          <Dropdown.Menu>
            <MenuItem href={config.HUNT_DOC} target="_blank">
              <span className="glyphicon glyphicon-book" /> User manual
            </MenuItem>
            <MenuItem onClick={this.AboutClick}>
              <span className="glyphicon glyphicon-question-sign" /> About Scirius
            </MenuItem>
          </Dropdown.Menu>
        </Dropdown>

        <Dropdown componentClass="li" id="user">
          <Dropdown.Toggle useAnchor className="nav-item-iconic">
            <Icon type="pf" name="user" /> {user}
          </Dropdown.Toggle>
          <Dropdown.Menu>
            <MenuItem href="/accounts/edit">
              <span className="glyphicon glyphicon-cog" /> Account settings
            </MenuItem>
            <MenuItem href="/accounts/logout">
              <span className="glyphicon glyphicon-log-out" /> Logout
            </MenuItem>
          </Dropdown.Menu>
        </Dropdown>

        <Modal show={this.state.showUpdateModal}>
          <Modal.Header>
            <button type="button" className="close" onClick={this.closeShowUpdate} aria-hidden="true" aria-label="Close">
              <Icon type="pf" name="close" />
            </button>

            <Modal.Title> Update threat detection </Modal.Title>
          </Modal.Header>

          <Modal.Body>
            {process.env.REACT_APP_HAS_TAG && (
              <Form horizontal>You are going to update threat detection (push ruleset and update post processing). Do you want to continue ?</Form>
            )}
            {!process.env.REACT_APP_HAS_TAG && (
              <Form horizontal>You are going to update threat detection (update/push ruleset). Do you want to continue ?</Form>
            )}
          </Modal.Body>

          <Modal.Footer>
            <Button bsStyle="default" className="btn-cancel" onClick={this.closeShowUpdate}>
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
          altLogo="SSP Logo"
          trademarkText="Copyright 2014-2021, Stamus Networks"
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
  children: PropTypes.any,
  interval: PropTypes.any,
  systemSettings: PropTypes.any,
  needReload: PropTypes.any,
  ChangeRefreshInterval: PropTypes.any,
  switchPage: PropTypes.any,
  duration: PropTypes.any,
  user: PropTypes.shape({
    pk: PropTypes.any,
    timezone: PropTypes.any,
    username: PropTypes.any,
    firstName: PropTypes.any,
    lastName: PropTypes.any,
    isActive: PropTypes.any,
    email: PropTypes.any,
    dateJoined: PropTypes.any,
    permissions: PropTypes.any,
  }),
};

export default compose(withPermissions)(UserNavInfo);
