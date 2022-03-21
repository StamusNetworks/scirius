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
import { VerticalNav, VerticalNavItem } from 'patternfly-react';
import { Modal } from 'antd';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';
import axios from 'axios';
import VerticalNavItems from 'components/VerticalNavItems';
import DisplayPage from 'components/DisplayPage';
import { PAGE_STATE } from 'constants';
import * as config from 'config/Api';
import UserNavInfo from 'containers/UserNavInfo';
import 'antd/dist/antd.min.css';
import EmitEvent from '../../helpers/EmitEvent';
import '../../pygments.css';
// eslint-disable-next-line import/no-unresolved
import '../../css/HuntApp.css';
import sciriusLogo from '../../img/stamus.png';
import keymap from '../../Keymap';
import ErrorHandler from '../../components/Error';
import storage from '../../helpers/storage';
import Breadcrumb from '../../components/Breadcrumb';

const shortcutManager = new ShortcutManager(keymap);

export default class HuntApp extends Component {
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
          perPageOptions: [6, 10, 15, 25],
        },
        sort: { id: 'created', asc: false },
        view_type: 'list',
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
          perPage: 100,
          perPageOptions: [20, 50, 100],
        },
        sort: { id: 'timestamp', asc: false },
        view_type: 'list',
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
          perPageOptions: [20, 50, 100],
        },
        sort: { id: 'timestamp', asc: false },
        view_type: 'list',
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
          perPageOptions: [6, 10, 15, 25, 50],
        },
        sort: { id: 'date', asc: false },
        view_type: 'list',
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
    setInterval(this.getSciriusStatus, 10000);
    axios.get(config.API_URL + config.SYSTEM_SETTINGS_PATH).then((systemSettings) => {
      this.setState({ systemSettings: systemSettings.data });
    });

    if (this.state.interval) {
      this.timer = setInterval(this.needReload, this.state.interval * 1000);
    }
  }

  needReload() {
    this.props.reload();
  }

  changeRefreshInterval(interval) {
    this.setState({ interval });
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

    if (this.props.duration) {
      this.props.reload();
    }
  }

  updateRuleListState(rulesListState, fetchDataCallback) {
    this.setState({ rules_list: rulesListState }, fetchDataCallback);
    storage.setItem('rules_list', JSON.stringify(rulesListState));
  }

  updateAlertListState(alertsListState, fetchDataCallback) {
    this.setState({ alerts_list: alertsListState }, fetchDataCallback);
    storage.setItem('alerts_list', JSON.stringify(alertsListState));
  }

  updateFilterListState(filtersListState, fetchDataCallback) {
    this.setState({ filters_list: filtersListState }, fetchDataCallback);
    storage.setItem('filters_list', JSON.stringify(filtersListState));
  }

  updateHistoryFilterState(filters, fetchDataCallback) {
    this.setState({ historyFilters: filters }, fetchDataCallback);
    storage.setItem('history_filters', JSON.stringify(filters));
  }

  updateHistoryListState(historyState, fetchDataCallback) {
    this.setState({ history: historyState }, fetchDataCallback);
    storage.setItem('history', JSON.stringify(historyState));
  }

  getSciriusStatus = () => {
    axios({
      method: 'get',
      url: '/rules/info',
      timeout: 15000,
    })
      .then((data) => {
        if (!data) {
          if (this.state.hasConnectivity) {
            this.setState({
              hasConnectivity: false,
            });
          }
        } else {
          if (data.data.status === 'green' && !this.state.hasConnectivity) {
            this.setState({
              hasConnectivity: true,
            });
          }
          if (data.data.status !== 'green' && this.state.hasConnectivity) {
            this.setState({
              hasConnectivity: false,
              connectionProblem: 'Scirius does not feel comfortable',
            });
          }
        }
      })
      .catch(() => {
        if (this.state.hasConnectivity) {
          this.setState({
            hasConnectivity: false,
            connectionProblem: 'No connection with scirius. This pop-up will disappear if connection is restored.',
          });
        }
      });
  };

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
              <img
                src={sciriusLogo}
                height={32}
                width={116}
                style={{ marginTop: 7, marginBottom: -7, marginLeft: 20, display: 'block', float: 'left' }}
                alt="logo"
              />
            </VerticalNav.Brand>
            <Breadcrumb currentPage={this.state.display} />
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
          {VerticalNavItems.filter((v) => !v.permission || this.props.user.permissions.includes(v.permission)).map((v) => (
            <VerticalNavItem
              title={v.title}
              iconClass={v.iconClass}
              key={Math.random()}
              onClick={() => this.switchPage(v.def, undefined)}
              active={this.state.display.page === v.def}
            />
          ))}
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
                  updateFilterListState={this.updateFilterListState}
                  updateFiltersFilterState={this.updateFiltersFilterState}
                  updateHostListState={this.updateHostListState}
                  hosts_list={this.state.hosts_list}
                />
              </ErrorHandler>
            </div>
          </div>
        </div>

        <Modal title="Scirius is down" visible={!this.state.hasConnectivity} footer={null}>
          <div className="modal-body text-danger">{this.state.connectionProblem}</div>
        </Modal>
      </div>
    );
  }
}

HuntApp.childContextTypes = {
  shortcuts: PropTypes.object.isRequired,
};

HuntApp.propTypes = {
  reload: PropTypes.func.isRequired,
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
