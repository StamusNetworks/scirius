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
import { withRouter } from 'react-router';
import { Table } from 'antd';
import axios from 'axios';
import * as config from 'config/Api';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import HistoryItem from 'ui/components/HistoryItem';
import ErrorHandler from 'ui/components/Error';
import moment from 'moment';
import buildListParams from 'ui/helpers/buildListParams';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { createStructuredSelector } from 'reselect';
import injectReducer from 'ui/utils/injectReducer';
import injectSaga from 'ui/utils/injectSaga';
import filtersActions from 'ui/stores/filters/actions';
import reducer from 'ui/stores/filters/reducer';
import saga from 'ui/stores/filters/saga';
import { addFilter, makeSelectHistoryFilters } from 'ui/containers/HuntApp/stores/global';
import { buildFilter, buildListUrlParams } from '../../helpers/common';
import HuntPaginationRow from '../../HuntPaginationRow';

class HistoryPage extends React.Component {
  constructor(props) {
    super(props);

    const historyConf = buildListParams(JSON.parse(localStorage.getItem('history')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'date', asc: false },
      view_type: 'list',
    });

    this.state = { data: [], count: 0, history: historyConf };
    this.fetchData = this.fetchData.bind(this);
    this.buildFilter = buildFilter;

    this.props.getActionTypes();
  }

  componentDidMount() {
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)) {
      this.fetchData();
    }
  }

  updateHistoryListState = historyState => {
    this.setState({ history: historyState }, () => this.fetchData());
    localStorage.setItem('history', JSON.stringify(historyState));
  };

  fetchData() {
    const stringFilters = this.buildFilter(this.props.filters);
    const listParams = buildListUrlParams(this.state.history);
    this.setState({ loading: true });
    axios
      .get(`${config.API_URL}${config.HISTORY_PATH}?${listParams}${stringFilters}`)
      .then(res => {
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

  columns = [
    {
      title: 'Operation',
      dataIndex: 'operation',
    },
    {
      title: 'Message',
      dataIndex: 'message',
    },
    {
      title: 'Date',
      dataIndex: 'date',
    },
    {
      title: 'User',
      dataIndex: 'user',
    },
    {
      title: 'IP',
      dataIndex: 'ip',
    },
    {
      title: 'Ruleset',
      dataIndex: 'ruleset',
    },
    {
      title: 'Signature',
      dataIndex: 'signature',
    },
  ];

  render() {
    let expand = false;
    for (let filter = 0; filter < this.props.filters; filter += 1) {
      if (this.props.filters[filter].id === 'comment' || this.props.filters[filter].id === 'client_ip') {
        expand = true;
        break;
      }
    }

    const dataSource = this.state.data.results?.map(item => ({
      key: item.pk,
      operation: item.title,
      message: item.description,
      date: moment(item.date).format('YYYY-MM-DD, hh:mm:ss a'),
      user: item.username,
      ip: item.client_ip,
      ruleset: item.ua_objects.ruleset?.value,
      signature: item.ua_objects.rule?.sid && (
        <a
          onClick={() => {
            this.props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: item.ua_objects.rule.sid, negated: false });
            this.props.history.push('/stamus/hunting/signatures', item.ua_objects.rule.sid);
          }}
        >
          {item.ua_objects.rule.sid}
        </a>
      ),
      item, // we need this to access the item data in the `expandedRowRender` below
    }));

    return (
      <div>
        <ErrorHandler>
          <Filters
            page="HISTORY"
            section={sections.HISTORY}
            queryTypes={['all']}
            filterTypes={['all']}
            sortValues={{ option: this.state.history.sort.id, direction: this.state.history.sort.asc ? 'asc' : 'desc' }}
            onSortChange={(option, direction) => {
              this.updateHistoryListState({
                ...this.state.history,
                sort: {
                  id: option || this.state.history.sort.id,
                  asc: direction ? direction === 'asc' : this.state.history.sort.asc,
                },
              });
            }}
          />
        </ErrorHandler>
        {this.state.data.results && (
          <Table
            size="small"
            loading={this.state.loading}
            dataSource={dataSource}
            columns={this.columns}
            expandable={{
              columnWidth: 5,
              expandRowByClick: true,
              expandedRowRender: ({ item }) => <HistoryItem key={item.pk} data={item} expand_row={expand} />,
              rowExpandable: () => true,
            }}
            pagination={false}
          />
        )}
        <ErrorHandler>
          <HuntPaginationRow
            viewType="list"
            onPaginationChange={this.updateHistoryListState}
            itemsCount={this.state.count}
            itemsList={this.state.history}
          />
        </ErrorHandler>
      </div>
    );
  }
}

HistoryPage.propTypes = {
  filters: PropTypes.any,
  getActionTypes: PropTypes.func,
  addFilter: PropTypes.func,
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
  history: PropTypes.object,
};

const mapDispatchToProps = dispatch => ({
  getActionTypes: () => dispatch(filtersActions.historyFiltersRequest()),
  addFilter: (section, filter) => dispatch(addFilter(section, filter)),
});

const mapStateToProps = createStructuredSelector({
  filters: makeSelectHistoryFilters(),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);

const withReducer = injectReducer({ key: 'ruleSet', reducer });
const withSaga = injectSaga({ key: 'ruleSet', saga });

export default compose(withReducer, withSaga, withConnect, withRouter)(HistoryPage);
