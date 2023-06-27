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
import axios from 'axios';
import { Helmet } from 'react-helmet';
import md5 from 'md5';
import * as config from 'config/Api';
import { STAMUS } from 'ui/config';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'ui/buildFilterParams';
import ErrorHandler from 'ui/components/Error';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import buildListParams from 'ui/helpers/buildListParams';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import rulesSelectors from 'ui/stores/filters/selectors';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withStore } from 'ui/mobx/RootStoreProvider';
import { updateHitsStats } from '../../helpers/updateHitsStats';
import { buildListUrlParams, loadActions, buildFilter } from '../../helpers/common';
import RuleInList from '../../RuleInList';
import RulePage from '../../RulePage';
import HuntPaginationRow from '../../HuntPaginationRow';

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
  constructor(props) {
    super(props);

    const rulesListConf = buildListParams(JSON.parse(localStorage.getItem('rules_list')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      view_type: 'list',
      sort: { id: 'hits', asc: false },
    });

    this.state = {
      rules: [],
      sources: [],
      count: 0,
      loading: true,
      net_error: undefined,
      // eslint-disable-next-line react/no-unused-state
      supported_actions: [],
      updateCache: true,
      rulesList: rulesListConf,
    };
    this.cache = {};
    this.cachePage = 1;
    this.updateRulesState = this.updateRulesState.bind(this);
    this.updateSignatureListState = this.updateSignatureListState.bind(this);
    this.fetchHitsStats = this.fetchHitsStats.bind(this);
    this.loadActions = loadActions.bind(this);
    this.buildFilter = buildFilter.bind(this);
    this.fetchData = this.fetchData.bind(this);
  }

  componentDidMount() {
    const sid = this.findSID(this.props.store.commonStore.filters);
    if (sid !== undefined) {
      this.setState({ loading: false });
    } else {
      this.fetchData();
    }
  }

  componentDidUpdate(prevProps) {
    const filtersChanged =
      JSON.stringify(prevProps.store.commonStore.filtersWithAlert) !== JSON.stringify(this.props.store.commonStore.filtersWithAlert);
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) || filtersChanged) {
      const sid = this.findSID(this.props.store.commonStore.filtersWithAlert);
      if (sid !== undefined) {
        // eslint-disable-next-line react/no-did-update-set-state
        this.setState({
          loading: false,
        });
      } else {
        this.fetchData();
      }
      if (filtersChanged && this.props.store.commonStore.user?.permissions.includes('rules.ruleset_policy_edit')) {
        this.loadActions(this.props.store.commonStore.filtersWithAlert);
      }
    }
  }

  updateRuleListState(rulesListState, fetchDataCallback) {
    this.setState({ rulesList: rulesListState }, fetchDataCallback);
    localStorage.setItem('rules_list', JSON.stringify(rulesListState));
  }

  buildTimelineDataSet = tdata => {
    const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
    for (let key = 0; key < tdata.length; key += 1) {
      timeline.columns[0].push(tdata[key].date);
      timeline.columns[1].push(tdata[key].hits);
    }
    return timeline;
  };

  findSID = filters => {
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
    const stringFilters = this.buildFilter(this.props.store.commonStore.filtersWithAlert);
    const rulesStat = this.state.rulesList;
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
    const listParams = buildListUrlParams(rulesStat);
    axios
      .all([
        axios.get(`${config.API_URL + config.RULE_PATH}?${listParams}&${filterParams}&highlight=true${stringFilters}`),
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
          this.setState({ rules: RuleRes.data.results });
        }),
      )
      .catch(e => {
        // handle the case when non-existent page is requested
        if (e.response.status === 404 && this.state.rulesList.pagination.page !== 1) {
          const sigsListState = {
            ...this.state.rulesList,
            pagination: {
              ...this.state.rulesList.pagination,
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
    const qfilter = buildQFilter(this.props.store.commonStore.filtersWithAlert, this.props.store.commonStore.systemSettings);
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
    this.updateRuleListState(sigsListState, () => this.fetchData());
  }

  render() {
    const displayRule = this.findSID(this.props.store.commonStore.filters);
    const view = displayRule ? 'rule' : 'rules_list';
    return (
      <div>
        <Helmet>
          <title>{`${STAMUS} - Signatures`}</title>
        </Helmet>
        {this.state.net_error !== undefined && <div className="alert alert-danger">Problem with backend: {this.state.net_error.message}</div>}
        <ErrorHandler>
          <Filters
            page="RULES_LIST"
            section={sections.GLOBAL}
            queryTypes={['filter', 'rest', 'filter_host_id']}
            filterTypes={['filter', 'rest']}
            sortValues={{ option: this.state.rulesList.sort.id, direction: this.state.rulesList.sort.asc ? 'asc' : 'desc' }}
            onSortChange={(option, direction) => {
              this.updateSignatureListState({
                ...this.state.rulesList,
                sort: {
                  id: option || this.state.rulesList.sort.id,
                  asc: direction ? direction === 'asc' : this.state.rulesList.sort.asc,
                },
              });
            }}
          />
        </ErrorHandler>

        {view === 'rules_list' && (
          <RuleInList
            loading={this.state.loading}
            rules={this.state.rules}
            sources={this.state.sources}
            filterParams={this.props.filterParams}
            rulesets={this.props.rulesets}
          />
        )}
        <ErrorHandler>
          {view === 'rules_list' && (
            <HuntPaginationRow
              viewType="list"
              onPaginationChange={this.updateSignatureListState}
              itemsCount={this.state.count}
              itemsList={this.state.rulesList}
            />
          )}
          {view === 'rule' && (
            <RulePage
              systemSettings={this.props.store.commonStore.systemSettings}
              rule={displayRule}
              config={this.state.rulesList}
              filters={this.props.store.commonStore.filters}
              filterParams={this.props.filterParams}
              rulesets={this.props.rulesets}
            />
          )}
        </ErrorHandler>
      </div>
    );
  }
}

SignaturesPage.propTypes = {
  rulesets: PropTypes.array,
  store: PropTypes.object,
  filterParams: PropTypes.object.isRequired,
};

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
  rulesets: rulesSelectors.makeSelectRuleSets(),
});

const withConnect = connect(mapStateToProps);
export default compose(withConnect, withStore)(SignaturesPage);
