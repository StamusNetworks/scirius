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
import store from 'store';
import md5 from 'md5';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from 'hunt_common/buildQFilter';
import { buildFilterParams } from 'hunt_common/buildFilterParams';
import RuleToggleModal from 'hunt_common/RuleToggleModal';
import HuntFilter from '../../HuntFilter';
import HuntPaginationRow from '../../HuntPaginationRow';
import RuleCard from '../../RuleCard';
import DashboardPage from '../DashboardPage';
import RulePage from '../../RulePage';
import RuleInList from '../../RuleInList';
import List from '../../components/List/index';
import ErrorHandler from '../../components/Error';
import { actionsButtons, buildListUrlParams, loadActions, createAction, closeAction, buildFilter } from '../../helpers/common';
import { updateHitsStats } from '../../helpers/updateHitsStats';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

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
  },
];

export class SignaturesPage extends React.Component {
  // export class RulesList extends HuntList {
  constructor(props) {
    super(props);

    const huntFilters = store.get('huntFilters');
    const rulesFilters = typeof huntFilters !== 'undefined' && typeof huntFilters.ruleslist !== 'undefined' ? huntFilters.ruleslist.data : [];
    this.state = {
      rules: [],
      sources: [],
      rulesets: [],
      count: 0,
      loading: true,
      action: { view: false, type: 'suppress' },
      net_error: undefined,
      rulesFilters,
      // eslint-disable-next-line react/no-unused-state
      supported_actions: [],
      updateCache: true,
    };
    this.cache = {};
    this.cachePage = 1;
    this.updateRulesState = this.updateRulesState.bind(this);
    this.updateSignatureListState = this.updateSignatureListState.bind(this);
    this.fetchHitsStats = this.fetchHitsStats.bind(this);
    this.actionsButtons = actionsButtons.bind(this);
    this.buildListUrlParams = buildListUrlParams.bind(this);
    this.loadActions = loadActions.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
    this.buildFilter = buildFilter.bind(this);
    this.fetchData = this.fetchData.bind(this);
  }

  componentDidMount() {
    const sid = this.findSID(this.props.filters);
    if (this.state.rulesets.length === 0) {
      axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
        this.setState({ rulesets: res.data.results });
      });
    }
    if (sid !== undefined) {
      this.setState({ loading: false });
    } else {
      this.fetchData();
    }
    const huntFilters = store.get('huntFilters');
    axios.get(config.API_URL + config.HUNT_FILTER_PATH).then((res) => {
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
      if (typeof huntFilters === 'undefined' || typeof huntFilters.ruleslist === 'undefined' || huntFilters.ruleslist.checkSum !== currentCheckSum) {
        store.set('huntFilters', {
          ...huntFilters,
          ruleslist: {
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
      const sid = this.findSID(this.props.filtersWithAlert);
      if (sid !== undefined) {
        // eslint-disable-next-line react/no-did-update-set-state
        this.setState({
          loading: false,
        });
      } else {
        this.fetchData();
      }
      if (filtersChanged && this.props.user.permissions.includes('rules.ruleset_policy_edit')) {
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
  };

  findSID = (filters) => {
    let foundSid;
    for (let i = 0; i < filters.length; i += 1) {
      if (filters[i].id === 'alert.signature_id' && filters[i].negated === false) {
        foundSid = filters[i].value;
        break;
      }
    }
    return foundSid;
  };

  fetchData() {
    const stringFilters = this.buildFilter(this.props.filtersWithAlert);
    const rulesStat = this.props.rules_list;
    const hash = md5(
      `${rulesStat.pagination.page}|${rulesStat.pagination.perPage}|${JSON.stringify(this.props.filterParams)}|${rulesStat.sort.id}|${
        rulesStat.sort.asc
      }|${stringFilters}`,
    );
    if (typeof this.cache[hash] !== 'undefined') {
      this.processRulesData(this.cache[hash].RuleRes, this.cache[hash].SrcRes);
      return;
    }

    this.setState({ loading: true });
    const filterParams = buildFilterParams(this.props.filterParams);
    axios
      .all([
        axios.get(`${config.API_URL + config.RULE_PATH}?${this.buildListUrlParams(rulesStat)}&${filterParams}&highlight=true${stringFilters}`),
        axios.get(`${config.API_URL + config.SOURCE_PATH}?page_size=100`),
      ])
      .then(
        axios.spread((RuleRes, SrcRes) => {
          if (this.state.updateCache) {
            this.cachePage = rulesStat.pagination.page;
          } else {
            this.setState({ updateCache: true });
          }

          this.cache[hash] = { RuleRes, SrcRes };
          this.processRulesData(RuleRes, SrcRes);
        }),
      )
      .catch((e) => {
        // handle the case when non-existent page is requested
        if (e.response.status === 404 && this.props.rules_list.pagination.page !== 1) {
          const sigsListState = {
            ...this.props.rules_list,
            pagination: {
              ...this.props.rules_list.pagination,
              page: 1,
            },
          };

          this.updateSignatureListState(sigsListState);
          return;
        }

        this.setState({ net_error: e, loading: false });
      });
  }

  processRulesData(RuleRes, SrcRes) {
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
        this.fetchHitsStats(RuleRes.data.results);
      } else {
        this.buildHitsStats(RuleRes.data.results);
      }
    }
  }

  fetchHitsStats(rules) {
    const qfilter = buildQFilter(this.props.filtersWithAlert, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);
    updateHitsStats(rules, filterParams, this.updateRulesState, qfilter);
  }

  buildHitsStats(rules) {
    for (let rule = 0; rule < rules.length; rule += 1) {
      // eslint-disable-next-line no-param-reassign
      rules[rule].timeline = this.buildTimelineDataSet(rules[rule].timeline_data);
      // rules[rule].timeline_data = undefined;
    }
    this.updateRulesState(rules);
  }

  updateRulesState(rules) {
    this.setState({ rules });
  }

  updateSignatureListState(sigsListState) {
    this.props.updateListState(sigsListState, () => this.fetchData());
  }

  render() {
    const displayRule = this.findSID(this.props.filters);
    const view = displayRule ? 'rule' : 'rules_list';
    return (
      <div className="RulesList HuntList">
        {this.state.net_error !== undefined && <div className="alert alert-danger">Problem with backend: {this.state.net_error.message}</div>}
        <ErrorHandler>
          <HuntFilter
            config={this.props.rules_list}
            itemsListUpdate={this.updateSignatureListState}
            filterFields={this.state.rulesFilters}
            sort_config={RuleSortFields}
            displayToggle={view === 'rules_list'}
            actionsButtons={this.actionsButtons}
            queryType={['filter', 'rest', 'filter_host_id']}
            page={this.props.page}
            systemSettings={this.props.systemSettings}
          />
        </ErrorHandler>

        {view === 'rules_list' && <Spin spinning={this.state.loading} />}

        {view === 'rules_list' && (
          <List
            type={this.props.rules_list.view_type}
            items={this.state.rules}
            component={{ list: RuleInList, card: RuleCard }}
            itemProps={{
              sources: this.state.sources,
              filterParams: this.props.filterParams,
              rulesets: this.state.rulesets,
            }}
          />
        )}
        <ErrorHandler>
          {view === 'rules_list' && (
            <HuntPaginationRow
              viewType="list"
              onPaginationChange={this.updateSignatureListState}
              itemsCount={this.state.count}
              itemsList={this.props.rules_list}
            />
          )}
          {view === 'rule' && (
            <RulePage
              systemSettings={this.props.systemSettings}
              rule={displayRule}
              config={this.props.rules_list}
              filters={this.props.filters}
              filterParams={this.props.filterParams}
              rulesets={this.state.rulesets}
            />
          )}
          {view === 'dashboard' && <DashboardPage />}
        </ErrorHandler>

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

SignaturesPage.propTypes = {
  systemSettings: PropTypes.any,
  filters: PropTypes.any,
  filtersWithAlert: PropTypes.any,
  updateListState: PropTypes.any, // should be removed when redux is implemented
  rules_list: PropTypes.any, // should be removed when redux is implemented
  page: PropTypes.any,
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
