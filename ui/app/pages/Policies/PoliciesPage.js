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
import _ from 'lodash';
import moment from 'moment';
import styled from 'styled-components';
import { createStructuredSelector } from 'reselect';
import { Helmet } from 'react-helmet';
import { connect } from 'react-redux';
import { Table } from 'antd';

import * as config from 'config/Api';
import constants from 'ui/constants';
import ErrorHandler from 'ui/components/Error';
import FilterEditKebab from 'ui/components/FilterEditKebab';
import buildListParams from 'ui/helpers/buildListParams';
import PolicyParameters from 'ui/pages/Policies/PolicyParameters';
import { STAMUS } from 'ui/config';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import HuntPaginationRow from '../../HuntPaginationRow';
import ActionItem from '../../ActionItem';
import { buildListUrlParams } from '../../helpers/common';

const DescriptionItem = styled.div`
  padding: 0 10px;
`;

const FiltersCell = styled.div`
  display: flex;
  flex-direction: row;
`;

export class PoliciesPage extends React.Component {
  constructor(props) {
    super(props);

    const filtersListConf = buildListParams(JSON.parse(localStorage.getItem('filters_list')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'timestamp', asc: false },
    });

    this.state = { data: [], count: 0, rulesets: {}, filtersList: filtersListConf, expand: true };

    this.fetchData = this.fetchData.bind(this);
    this.needUpdate = this.needUpdate.bind(this);
    this.updateActionListState = this.updateActionListState.bind(this);
    this.setExpand = this.setExpand.bind(this);
  }

  componentDidMount() {
    if (_.isEmpty(this.state.rulesets)) {
      axios.get(`${config.API_URL}${config.RULESET_PATH}`).then(res => {
        const rulesets = {};
        for (let index = 0; index < res.data.results.length; index += 1) {
          rulesets[res.data.results[index].pk] = res.data.results[index];
        }
        this.setState({ rulesets });
        this.fetchData();
      });
    }
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams)) {
      this.fetchData();
    }
  }

  updateFilterListState(filtersListState, fetchDataCallback) {
    this.setState({ filtersList: filtersListState }, fetchDataCallback);
    localStorage.setItem('filters_list', JSON.stringify(filtersListState));
  }

  updateActionListState(rulesListState) {
    this.updateFilterListState(rulesListState, () => this.fetchData());
  }

  // eslint-disable-next-line no-unused-vars
  fetchData() {
    const listParams = buildListUrlParams(this.state.filtersList);
    this.setState({ loading: true });
    axios
      .get(`${config.API_URL}${config.PROCESSING_PATH}?${listParams}`)
      .then(res => {
        this.setState({ data: res.data.results, count: res.data.count, loading: false });
      })
      .catch(() => {
        this.setState({ loading: false });
      });
  }

  needUpdate() {
    this.fetchData();
  }

  setExpand(expand) {
    this.setState({ expand });
  }

  getRowRuleSets(item) {
    let rulesets = [];
    if (Object.keys(this.state.rulesets).length > 0) {
      rulesets = item.rulesets.map(item2 => <DescriptionItem key={Math.random()}>{this.state.rulesets[item2].name}</DescriptionItem>);
    }
    return rulesets;
  }

  getRowComment(item) {
    return (
      <React.Fragment>
        <DescriptionItem key="1">
          <b>username: </b>
          {item.username}
        </DescriptionItem>
        <DescriptionItem key="2">
          <b>creation date: </b>
          {moment(item.creation_date).format(constants.DATE_TIME_FORMAT)}
        </DescriptionItem>
        <DescriptionItem key="3">
          <b>comment: </b>
          {item.comment}
        </DescriptionItem>
      </React.Fragment>
    );
  }

  getRowDescription(item) {
    let description;
    if (item.action !== 'suppress') {
      // first handle the item.action `threshold` & `threat`
      if (item.action === 'threshold') {
        description = (
          <DescriptionItem key={Math.random()}>
            <strong>track</strong>: {item.options.track}
          </DescriptionItem>
        );
      } else if (item.action === 'threat') {
        description = (
          <DescriptionItem key={Math.random()}>
            <strong>threat</strong>: {item.options.threat}
          </DescriptionItem>
        );
      } else {
        // for all the other item.action types
        description = Object.keys(item.options).map(option => (
          <DescriptionItem key={Math.random()}>
            <strong>{option}</strong>: {item.options[option]}
          </DescriptionItem>
        ));
      }
    }
    return description;
  }

  getRowFilters(item, size) {
    const filters = [];
    const limit = size || item.filter_defs.length;
    for (let i = 0; i < limit; i += 1) {
      let info = (
        <DescriptionItem key={i}>
          {item.filter_defs[i].operator === 'different' && 'Not '}
          <strong>{item.filter_defs[i].key}</strong>: {item.filter_defs[i].value}
        </DescriptionItem>
      );
      if (item.filter_defs[i].key === 'alert.signature_id' && item.filter_defs[i].msg) {
        info = (
          <DescriptionItem key={i}>
            {item.filter_defs[i].operator === 'different' && 'Not '}
            <strong>{item.filter_defs[i].key}</strong>: {item.filter_defs[i].value} ({item.filter_defs[i].msg})
          </DescriptionItem>
        );
      }
      filters.push(info);
    }
    if (size && size < item.filter_defs.length) {
      filters.push(<span key="more">and {item.filter_defs.length - size} more...</span>);
    }
    return filters;
  }

  columns = [
    {
      title: 'Action',
      dataIndex: ['action'],
    },
    {
      title: 'Parameters',
      render: (value, item) => this.getRowDescription(item),
    },
    {
      title: 'Filters',
      render: (value, item) => <FiltersCell>{this.getRowFilters(item, 1)}</FiltersCell>,
    },
    {
      title: 'Rulesets',
      render: (value, item) => this.getRowRuleSets(item),
    },
    {
      title: 'Index',
      dataIndex: ['index'],
    },
    {
      title: 'Ctrl',
      dataIndex: 'ctrl',
      render: (value, item) => (
        <FilterEditKebab key={`${item.pk}-kebab`} data={item} last_index={this.state.count} needUpdate={this.needUpdate} setExpand={this.setExpand} />
      ),
    },
  ];

  render() {
    return (
      <div>
        <Helmet>
          <title>{`${STAMUS} - Policies`}</title>
        </Helmet>

        <Table
          rowKey={item => this.state.data?.findIndex(d => d.pk === item.pk)}
          style={{ marginTop: '10px', marginBottom: '10px' }}
          size="small"
          loading={this.state.loading}
          dataSource={this.state.data}
          columns={this.columns}
          expandable={{
            columnWidth: 5,
            expandRowByClick: this.state.expand,
            expandedRowRender: item => (
              <ActionItem
                expandedDescription={<PolicyParameters policy={item} />}
                filters={this.getRowFilters(item)}
                expandedRulesets={this.getRowRuleSets(item)}
                expandedComment={this.getRowComment(item)}
                key={item.pk}
                data={item}
                last_index={this.state.count}
                needUpdate={this.needUpdate}
                rulesets={this.state.rulesets}
                filterParams={this.props.filterParams}
              />
            ),
            rowExpandable: () => true,
          }}
          pagination={false}
        />
        <ErrorHandler>
          <HuntPaginationRow
            viewType="list"
            onPaginationChange={this.updateActionListState}
            itemsCount={this.state.count}
            itemsList={this.state.filtersList}
          />
        </ErrorHandler>
      </div>
    );
  }
}

PoliciesPage.propTypes = {
  filterParams: PropTypes.object.isRequired,
};

const mapStateToProps = createStructuredSelector({
  filterParams: makeSelectFilterParams(),
});

export default connect(mapStateToProps)(PoliciesPage);
