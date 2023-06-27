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
import { Table } from 'antd';
import { BellFilled } from '@ant-design/icons';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import { buildQFilter } from 'ui/buildQFilter';
import ErrorHandler from 'ui/components/Error';
import HuntRestError from 'ui/components/HuntRestError';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import moment from 'moment';
import buildListParams from 'ui/helpers/buildListParams';
import { addFilter, makeSelectGlobalFilters } from 'ui/containers/HuntApp/stores/global';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withStore } from 'ui/mobx/RootStoreProvider';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import { buildListUrlParams, loadActions } from '../../helpers/common';
import AlertItem from './components/AlertItem';
import HuntPaginationRow from '../../HuntPaginationRow';

class EventsPage extends React.Component {
  constructor(props) {
    super(props);

    const alertsListConf = buildListParams(JSON.parse(localStorage.getItem('alerts_list')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'timestamp', asc: false },
      view_type: 'list',
    });

    this.state = {
      alerts: [],
      loading: true,
      // eslint-disable-next-line react/no-unused-state
      net_error: undefined,
      // eslint-disable-next-line react/no-unused-state
      supported_actions: [],
      errors: null,
      count: 0,
      alertsList: alertsListConf,
    };
    this.fetchData = this.fetchData.bind(this);
    this.loadActions = loadActions.bind(this);
    this.updateAlertListState = this.updateAlertListState.bind(this);
  }

  componentDidMount() {
    this.fetchData();
    if (this.props.store.commonStore.user?.permissions.includes('rules.ruleset_policy_edit')) {
      this.loadActions();
    }
  }

  componentDidUpdate(prevProps) {
    const filtersChanged = JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert);
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) || filtersChanged) {
      this.fetchData();
      if (filtersChanged && this.props.store.commonStore.user?.permissions.includes('rules.ruleset_policy_edit')) {
        this.loadActions();
      }
    }
  }

  updateAlertListState(alertsListState, fetchDataCallback) {
    this.setState({ alertsList: alertsListState }, fetchDataCallback);
    localStorage.setItem('alerts_list', JSON.stringify(alertsListState));
  }

  updateRuleListState = rulesListState => {
    this.updateAlertListState(rulesListState, () => this.fetchData());
  };

  async fetchData() {
    const qfilter = buildQFilter(this.props.filtersWithAlert, this.props.store.commonStore.systemSettings);
    const paginationParams = buildListUrlParams(this.state.alertsList);

    this.setState({ loading: true });

    try {
      const data = await this.props.store.esStore.fetchAlertsTail(paginationParams, qfilter);
      if (data !== null && data.results && typeof data.results !== 'string') {
        this.setState({ alerts: data.results, count: data.count, loading: false });
      } else {
        this.setState({ loading: false });
      }
    } catch (error) {
      if (error.response.status === 500) {
        this.setState({ errors: [`${error.response.data[0].slice(0, 160)}...`], loading: false });
        return;
      }
      this.setState({ errors: null, loading: false });
    }
  }

  getIconColor(key) {
    if (key === 'informational') return '#7b1244';
    if (key === 'relevant') return '#ec7a08';
    return '#005792';
  }

  columns = [
    {
      title: '',
      render: (e, row) => (
        <div>
          <BellFilled style={{ color: this.getIconColor(row.tag) }} />
        </div>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
    },
    {
      title: 'Method',
      dataIndex: 'method',
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
    },
    {
      title: 'Destination IP',
      dataIndex: 'destination_ip',
    },
    {
      title: 'Proto',
      dataIndex: 'proto',
    },
    {
      title: 'Probe',
      dataIndex: 'probe',
    },
    {
      title: 'Category',
      dataIndex: 'category',
    },
    {
      title: 'Tag',
      dataIndex: 'tag',
    },
  ];

  render() {
    const dataSource = this.state.alerts.map(rule => ({
      // eslint-disable-next-line no-underscore-dangle
      key: rule._id,
      timestamp: moment(rule.timestamp).format('YYYY-MM-DD, hh:mm:ss a'),
      method: rule.alert.signature,
      source_ip: rule.src_ip,
      destination_ip: rule.dest_ip,
      proto: rule.app_proto || rule.proto,
      probe: rule.host,
      category: rule.alert.category,
      tag: rule.alert.tag || 'untagged',
      rule, // we need this to access the rule data in the `expandedRowRender` below
    }));

    return (
      <div>
        <Helmet>
          <title>{`${STAMUS} - Events`}</title>
        </Helmet>

        {this.state.errors && <HuntRestError errors={this.state.errors} />}
        <ErrorHandler>
          <Filters page="ALERTS_LIST" section={sections.GLOBAL} queryTypes={['filter', 'filter_host_id']} filterTypes={['filter']} />
        </ErrorHandler>

        {this.state.alerts && (
          <Table
            data-test="alerts-table"
            size="small"
            loading={this.state.loading}
            dataSource={dataSource}
            columns={this.columns}
            expandable={{
              columnWidth: 5,
              expandRowByClick: true,
              expandedRowRender: alert => (
                <AlertItem
                  data={alert.rule}
                  filterParams={this.props.filterParams}
                  filters={this.props.filters}
                  addFilter={this.props.addFilter}
                  eventTypes={this.props.store.commonStore.eventTypes}
                />
              ),
              rowExpandable: () => true,
            }}
            pagination={false}
          />
        )}
        <ErrorHandler>
          <HuntPaginationRow
            viewType="list"
            onPaginationChange={this.updateRuleListState}
            itemsCount={this.state.count}
            itemsList={this.state.alertsList}
          />
        </ErrorHandler>
      </div>
    );
  }
}

EventsPage.propTypes = {
  filters: PropTypes.any,
  filtersWithAlert: PropTypes.any,
  store: PropTypes.object,
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

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  filterParams: makeSelectFilterParams(),
});

const mapDispatchToProps = {
  addFilter,
};

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default compose(withConnect, withStore)(EventsPage);
