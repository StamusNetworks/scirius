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
import { List, Spin } from 'antd';
import axios from 'axios';
import store from 'store';
import md5 from 'md5';
import * as config from 'config/Api';
import { buildQFilter } from 'buildQFilter';
import { buildFilterParams } from 'buildFilterParams';
import RuleToggleModal from 'RuleToggleModal';
import HuntFilter from '../../HuntFilter';
import AlertItem from './components/AlertItem';
import { actionsButtons, buildListUrlParams, loadActions, createAction, closeAction } from '../../helpers/common';
import ErrorHandler from 'ui/components/Error';
import HuntRestError from 'ui/components/HuntRestError';

export class AlertsPage extends React.Component {
  constructor(props) {
    super(props);

    const huntFilters = store.get('huntFilters');
    const rulesFilters = typeof huntFilters !== 'undefined' && typeof huntFilters.alertslist !== 'undefined' ? huntFilters.alertslist.data : [];
    this.state = {
      alerts: [],
      rulesets: [],
      loading: true,
      action: { view: false, type: 'suppress' },
      // eslint-disable-next-line react/no-unused-state
      net_error: undefined,
      rulesFilters,
      // eslint-disable-next-line react/no-unused-state
      supported_actions: [],
      errors: null,
    };
    this.fetchData = this.fetchData.bind(this);
    this.actionsButtons = actionsButtons.bind(this);
    this.buildListUrlParams = buildListUrlParams.bind(this);
    this.loadActions = loadActions.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
  }

  componentDidMount() {
    this.fetchData();
    if (this.state.rulesets.length === 0) {
      axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
        this.setState({ rulesets: res.data.results });
      });
    }
    const huntFilters = store.get('huntFilters');
    axios.get(config.API_URL + config.HUNT_FILTER_PATH).then((res) => {
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
        this.setState({ rulesFilters: fdata });
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

  fetchData() {
    const stringFilters = buildQFilter(this.props.filtersWithAlert, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);
    const listParams = this.buildListUrlParams(this.props.rules_list);
    this.setState({ loading: true });

    const url = `${config.API_URL + config.ES_BASE_PATH}alerts_tail/?${listParams}&${filterParams}${stringFilters}`;
    axios
      .get(url)
      .then((res) => {
        if (res.data !== null && res.data.results && typeof res.data.results !== 'string') {
          this.setState({ alerts: res.data.results, loading: false });
        } else {
          this.setState({ loading: false });
        }
      })
      .catch((error) => {
        if (error.response.status === 500) {
          this.setState({ errors: [`${error.response.data[0].slice(0, 160)}...`], loading: false });
          return;
        }
        this.setState({ errors: null, loading: false });
      });
  }

  updateRuleListState(rulesListState, fetchDataCallback) {
    this.props.updateListState(rulesListState, fetchDataCallback);
  }

  render() {
    return (
      <div className="AlertsList HuntList">
        {this.state.errors && <HuntRestError errors={this.state.errors} />}
        <ErrorHandler>
          <HuntFilter
            config={this.props.rules_list}
            ActiveSort={this.props.rules_list.sort}
            UpdateSort={this.UpdateSort}
            filterFields={this.state.rulesFilters}
            sort_config={undefined}
            actionsButtons={this.actionsButtons}
            queryType={['filter', 'filter_host_id']}
            page={this.props.page}
            systemSettings={this.props.systemSettings}
          />
        </ErrorHandler>
        <Spin spinning={this.state.loading} />
        {this.state.alerts && (
          <List
            size="small"
            header={null}
            footer={null}
            dataSource={this.state.alerts}
            renderItem={(rule) => {
              const { _id: ruleId, _source: ruleSource } = rule;
              return (
                <ErrorHandler key={ruleId}>
                  <AlertItem
                    key={ruleId}
                    id={ruleId}
                    data={ruleSource}
                    filterParams={this.props.filterParams}
                    filters={this.props.filters}
                    addFilter={this.props.addFilter}
                  />
                </ErrorHandler>
              );
            }}
          />
        )}
        <ErrorHandler>
          {this.state.action.view && (
            <RuleToggleModal
              show={this.state.action.view}
              action={this.state.action.type}
              config={this.props.rules_list}
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
  rules_list: PropTypes.any,
  filters: PropTypes.any,
  filtersWithAlert: PropTypes.any,
  systemSettings: PropTypes.any,
  updateListState: PropTypes.any,
  page: PropTypes.any,
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
