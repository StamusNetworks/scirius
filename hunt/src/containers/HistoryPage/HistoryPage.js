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
import { ListView, Spinner, PAGINATION_VIEW } from 'patternfly-react';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { sections } from 'hunt_common/constants';
import HuntFilter from '../../HuntFilter';
import HistoryItem from '../../components/HistoryItem';
import HuntPaginationRow from '../../HuntPaginationRow';
import ErrorHandler from '../../components/Error';
import { buildFilter, buildListUrlParams } from '../../helpers/common';

const HistorySortFields = [
  {
    id: 'date',
    title: 'Date',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'username',
    title: 'User',
    isNumeric: false,
    defaultAsc: false,
  },
  {
    id: 'client_ip',
    title: 'Client IP',
    isNumeric: false,
    defaultAsc: false,
  },
];

export default class HistoryPage extends React.Component {
  constructor(props) {
    super(props);
    const HistoryFilterFields = [
      {
        id: 'username',
        title: 'User',
        placeholder: 'Filter by User',
        filterType: 'text',
        queryType: 'all',
      },
      {
        id: 'comment',
        title: 'Comment',
        placeholder: 'Filter by Comment',
        filterType: 'text',
        queryType: 'all',
      },
      {
        id: 'action_type',
        title: 'Action Type',
        placeholder: 'Filter by Action Type',
        filterType: 'select',
        filterValues: [],
        queryType: 'all',
      },
      {
        id: 'client_ip',
        title: 'Client IP',
        placeholder: 'Filter by Client IP',
        filterType: 'text',
        filterValues: [],
        queryType: 'all',
      },
    ];
    this.state = { data: [], count: 0, filterFields: HistoryFilterFields };
    this.fetchData = this.fetchData.bind(this);
    this.buildFilter = buildFilter;
    this.buildListUrlParams = buildListUrlParams.bind(this);
    this.updateHistoryListState = this.updateHistoryListState.bind(this);

    this.props.getActionTypes();
  }

  componentDidMount() {
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)) {
      this.fetchData();
    }
    if (prevProps.actionTypesList.length !== this.props.actionTypesList.length) {
      const filterFields = [...this.state.filterFields];
      filterFields.find((field) => field.id === 'action_type').filterValues = this.props.actionTypesList;
      // eslint-disable-next-line react/no-did-update-set-state
      this.setState({
        filterFields,
      });
    }
  }

  fetchData() {
    const stringFilters = this.buildFilter(this.props.filters);
    const listParams = this.buildListUrlParams(this.props.rules_list);
    this.setState({ loading: true });
    axios
      .get(`${config.API_URL}${config.HISTORY_PATH}?${listParams}${stringFilters}`)
      .then((res) => {
        this.setState({
          data: res.data,
          count: res.data.count,
          loading: false,
        });
      })
      .catch(() => {
        this.setState({ loading: false });
      });
  }

  updateHistoryListState(rulesListState) {
    this.props.updateListState(rulesListState, () => this.fetchData());
  }

  render() {
    let expand = false;
    for (let filter = 0; filter < this.props.filters; filter += 1) {
      if (this.props.filters[filter].id === 'comment' || this.props.filters[filter].id === 'client_ip') {
        expand = true;
        break;
      }
    }
    return (
      <div className="HistoryList HuntList">
        <ErrorHandler>
          <HuntFilter
            config={this.props.rules_list}
            itemsListUpdate={this.updateHistoryListState}
            filterFields={this.state.filterFields}
            sort_config={HistorySortFields}
            queryType={['all']}
            gotAlertTag={false}
            page={this.props.page}
            filterType={sections.HISTORY}
            systemSettings={this.props.systemSettings}
          />
        </ErrorHandler>
        <Spinner loading={this.state.loading}></Spinner>
        <ListView>
          {this.state.data.results &&
            this.state.data.results.map((item) => <HistoryItem key={item.pk} data={item} switchPage={this.props.switchPage} expand_row={expand} />)}
        </ListView>
        <ErrorHandler>
          <HuntPaginationRow
            viewType={PAGINATION_VIEW.LIST}
            onPaginationChange={this.updateHistoryListState}
            itemsCount={this.state.count}
            itemsList={this.props.rules_list}
          />
        </ErrorHandler>
      </div>
    );
  }
}

HistoryPage.propTypes = {
  rules_list: PropTypes.any,
  filters: PropTypes.any,
  switchPage: PropTypes.any,
  updateListState: PropTypes.any,
  getActionTypes: PropTypes.func,
  actionTypesList: PropTypes.array,
  systemSettings: PropTypes.any,
  page: PropTypes.any,
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
