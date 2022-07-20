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
import { Spin } from 'antd';
import axios from 'axios';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import store from 'store';
import md5 from 'md5';
import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'ui/buildFilterParams';
import RuleToggleModal from 'RuleToggleModal';
import ErrorHandler from 'ui/components/Error';
import HuntRestError from 'ui/components/HuntRestError';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import { ArrowRightOutlined, InfoCircleOutlined, FileOutlined } from '@ant-design/icons';
import moment from 'moment';
import UICollapse from 'ui/components/UIElements/UICollapse';
import UIPanel from 'ui/components/UIElements/UIPanel/UIPanel';
import UIPanelHeader from 'ui/components/UIElements/UIPanel/UIPanelHeader';
import buildListParams from 'ui/helpers/buildListParams';
import AlertItem from './components/AlertItem';
import { actionsButtons, buildListUrlParams, loadActions, createAction, closeAction } from '../../helpers/common';

export class AlertsPage extends React.Component {
  constructor(props) {
    super(props);

    const alertsListConf = buildListParams(JSON.parse(localStorage.getItem('alerts_list')), {
      pagination: {
        page: 1,
        perPage: 100,
        perPageOptions: [20, 50, 100],
      },
      sort: { id: 'timestamp', asc: false },
      view_type: 'list',
    });

    this.state = {
      alerts: [],
      rulesets: [],
      loading: true,
      action: { view: false, type: 'suppress' },
      // eslint-disable-next-line react/no-unused-state
      net_error: undefined,
      // eslint-disable-next-line react/no-unused-state
      supported_actions: [],
      errors: null,
      alertsList: alertsListConf,
    };
    this.fetchData = this.fetchData.bind(this);
    this.actionsButtons = actionsButtons.bind(this);
    this.loadActions = loadActions.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
  }

  componentDidMount() {
    this.fetchData();
    if (this.state.rulesets.length === 0) {
      axios.get(config.API_URL + config.RULESET_PATH).then(res => {
        this.setState({ rulesets: res.data.results });
      });
    }
    const huntFilters = store.get('huntFilters');
    axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(res => {
      const fdata = [];
      const keys = Object.keys(res.data);
      const values = Object.values(res.data);
      for (let i = 0; i < keys.length; i += 1) {
        /* Only ES filter are allowed for Alert page */
        if (['filter'].indexOf(values[i].queryType) !== -1) {
          if (values[i].filterType !== 'hunt') {
            fdata.push(values[i]);
          }
        }
      }
      const currentCheckSum = md5(JSON.stringify(fdata));
      if (
        typeof huntFilters === 'undefined' ||
        typeof huntFilters.alertslist === 'undefined' ||
        huntFilters.alertslist.checkSum !== currentCheckSum
      ) {
        store.set('huntFilters', {
          ...huntFilters,
          alertslist: {
            checkSum: currentCheckSum,
            data: fdata,
          },
        });
      }
    });
    if (this.props.user.permissions.includes('rules.ruleset_policy_edit')) {
      this.loadActions();
    }
  }

  componentDidUpdate(prevProps) {
    const filtersChanged = JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert);
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) || filtersChanged) {
      this.fetchData();
      if (filtersChanged && this.props.user.permissions.includes('rules.ruleset_policy_edit')) {
        this.loadActions();
      }
    }
  }

  updateAlertListState(alertsListState, fetchDataCallback) {
    this.setState({ alertsList: alertsListState }, fetchDataCallback);
    localStorage.setItem('alerts_list', JSON.stringify(alertsListState));
  }

  fetchData() {
    const stringFilters = buildQFilter(this.props.filtersWithAlert, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);
    const listParams = buildListUrlParams(this.state.alertsList);
    this.setState({ loading: true });

    const url = `${config.API_URL + config.ES_BASE_PATH}alerts_tail/?${listParams}&${filterParams}${stringFilters}`;
    axios
      .get(url)
      .then(res => {
        if (res.data !== null && res.data.results && typeof res.data.results !== 'string') {
          this.setState({ alerts: res.data.results, loading: false });
        } else {
          this.setState({ loading: false });
        }
      })
      .catch(error => {
        if (error.response.status === 500) {
          this.setState({ errors: [`${error.response.data[0].slice(0, 160)}...`], loading: false });
          return;
        }
        this.setState({ errors: null, loading: false });
      });
  }

  updateRuleListState(rulesListState, fetchDataCallback) {
    this.updateAlertListState(rulesListState, fetchDataCallback);
  }

  render() {
    return (
      <div className="AlertsList">
        <Helmet>
          <title>{`${STAMUS} - Alerts`}</title>
        </Helmet>

        {this.state.errors && <HuntRestError errors={this.state.errors} />}
        <ErrorHandler>
          <Filters page="ALERTS" section={sections.GLOBAL} queryTypes={['filter']} />
        </ErrorHandler>

        <Spin spinning={this.state.loading} style={{ display: 'flex', justifyContent: 'center', margin: '15px 0 10px 0' }} />

        {this.state.alerts && (
          <UICollapse>
            {this.state.alerts.map(rule => {
              const { _id: ruleId, src_ip: srcIp, dest_ip: destIp, timestamp, app_proto: appProto, host, alert } = rule;

              const ipParams = (
                <React.Fragment>
                  {srcIp} <ArrowRightOutlined /> {destIp}
                </React.Fragment>
              );

              const addInfo = [
                <div key="timestamp" style={{ paddingLeft: 10 }}>
                  {moment(timestamp).format('YYYY-MM-DD, hh:mm:ss a')}
                </div>,
                <div key="app_proto" style={{ paddingLeft: 10 }}>
                  <strong>proto</strong>: {appProto}
                </div>,
                <div key="host" style={{ paddingLeft: 10 }}>
                  <strong>probe</strong>: {host}
                </div>,
              ];
              if (alert.category) {
                addInfo.push(
                  <div key="category" style={{ paddingLeft: 10 }}>
                    <strong>category</strong>: {alert.category}
                  </div>,
                );
              }
              let iconclass = <FileOutlined />;
              if (alert.tag) {
                addInfo.push(
                  <div key="tag" style={{ paddingLeft: 10 }}>
                    <strong>tag</strong>: {alert.tag}
                  </div>,
                );
                iconclass = <InfoCircleOutlined />;
              }

              return (
                <UIPanel
                  key={ruleId}
                  showArrow={false}
                  extra={<React.Fragment></React.Fragment>}
                  header={<UIPanelHeader sub1={iconclass} sub2={ipParams} sub3={<div>{alert.signature}</div>} sub4={addInfo} />}
                >
                  <AlertItem
                    key={ruleId}
                    id={ruleId}
                    data={rule}
                    filterParams={this.props.filterParams}
                    filters={this.props.filters}
                    addFilter={this.props.addFilter}
                  />
                </UIPanel>
              );
            })}
          </UICollapse>
        )}
        <ErrorHandler>
          {this.state.action.view && (
            <RuleToggleModal
              show={this.state.action.view}
              action={this.state.action.type}
              config={this.state.alertsList}
              filters={this.props.filters}
              close={this.closeAction}
              rulesets={this.state.rulesets}
              systemSettings={this.props.systemSettings}
              filterParams={this.props.filterParams}
            />
          )}
        </ErrorHandler>
      </div>
    );
  }
}

AlertsPage.propTypes = {
  filters: PropTypes.any,
  filtersWithAlert: PropTypes.any,
  systemSettings: PropTypes.any,
  addFilter: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
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
