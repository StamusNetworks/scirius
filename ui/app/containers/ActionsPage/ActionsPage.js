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
import { Table } from 'antd';
import * as config from 'config/Api';
import { STAMUS } from 'ui/config';
import ErrorHandler from 'ui/components/Error';
import FilterEditKebab from 'ui/components/FilterEditKebab';
import styled from 'styled-components';
import HuntPaginationRow from '../../HuntPaginationRow';
import ActionItem from '../../ActionItem';
import { actionsButtons, buildListUrlParams, createAction, closeAction, buildFilter } from '../../helpers/common';

const DescriptionItem = styled.div`
  padding: 0 10px;
`;

export class ActionsPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: [], count: 0, rulesets: [], expand: true };

    this.buildFilter = buildFilter.bind(this);
    this.actionsButtons = actionsButtons.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
    this.fetchData = this.fetchData.bind(this);
    this.needUpdate = this.needUpdate.bind(this);
    this.buildListUrlParams = buildListUrlParams.bind(this);
    this.updateActionListState = this.updateActionListState.bind(this);
    this.setExpand = this.setExpand.bind(this);
  }

  componentDidMount() {
    if (this.state.rulesets.length === 0) {
      axios.get(`${config.API_URL}${config.RULESET_PATH}`).then(res => {
        const rulesets = {};
        for (let index = 0; index < res.data.results.length; index += 1) {
          rulesets[res.data.results[index].pk] = res.data.results[index];
        }
        this.setState({ rulesets });
      });
    }
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams)) {
      this.fetchData();
    }
  }

  updateActionListState(rulesListState) {
    this.props.updateListState(rulesListState, () => this.fetchData());
  }

  // eslint-disable-next-line no-unused-vars
  fetchData() {
    const listParams = this.buildListUrlParams(this.props.rules_list);
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

  getDescriptionAddinfo(item) {
    const filters = [];
    for (let i = 0; i < item.filter_defs.length; i += 1) {
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

    let rulesets = [];
    if (Object.keys(this.state.rulesets).length > 0) {
      rulesets = item.rulesets.map(item2 => <DescriptionItem key={Math.random()}>{this.state.rulesets[item2].name}</DescriptionItem>);
    }

    // description
    let description;
    let expandedDescription = [];
    if (item.action !== 'suppress') {
      // first handle the item.action `threshold` & `threat`
      if (item.action === 'threshold') {
        description = (
          <DescriptionItem key={Math.random()}>
            <strong>track</strong>: {item.options.track}
          </DescriptionItem>
        );

        expandedDescription = Object.keys(item.options).map(option => {
          if (option === 'all_tenants' || option === 'no_tenant' || option === 'tenants') return null;
          if (option === 'tenants_str' && this.props.multiTenancy) {
            return (
              <DescriptionItem key="tenants_str">
                <strong>tenants</strong>: {item.options[option].join()}
              </DescriptionItem>
            );
          }
          return (
            <DescriptionItem key={Math.random()}>
              <strong>{option}</strong>: {item.options[option]}
            </DescriptionItem>
          );
        });
      } else if (item.action === 'threat') {
        description = (
          <DescriptionItem key={Math.random()}>
            <strong>threat</strong>: {item.options.threat}
          </DescriptionItem>
        );

        expandedDescription = Object.keys(item.options).map(option => {
          if (option === 'all_tenants' || option === 'no_tenant' || option === 'tenants') return null;
          if (option === 'tenants_str' && this.props.multiTenancy) {
            return (
              <DescriptionItem key="tenants_str">
                <strong>tenants</strong>: {item.options[option].join()}
              </DescriptionItem>
            );
          }
          return (
            <DescriptionItem key={Math.random()}>
              <strong>{option}</strong>: {item.options[option]}
            </DescriptionItem>
          );
        });
      } else {
        // for all the other item.action types
        description = Object.keys(item.options).map(option => (
          <DescriptionItem key={Math.random()}>
            <strong>{option}</strong>: {item.options[option]}
          </DescriptionItem>
        ));
        expandedDescription = description;
      }
    }

    return { description, filters, rulesets, expandedDescription };
  }

  columns = [
    {
      title: 'Action',
      dataIndex: 'action',
    },
    {
      title: 'Parameters',
      dataIndex: 'parameters',
    },
    {
      title: 'Filters',
      dataIndex: 'filters',
    },
    {
      title: 'Rulesets',
      dataIndex: 'rulesets',
    },
    {
      title: 'Index',
      dataIndex: 'index',
    },
    {
      title: 'Ctrl',
      dataIndex: 'ctrl',
    },
  ];

  render() {
    const dataSource = this.state.data.map(item => {
      const { description, filters, rulesets, expandedDescription } = this.getDescriptionAddinfo(item);
      return {
        key: item.pk,
        action: item.action,
        parameters: description,
        filters,
        rulesets,
        index: item.index,
        ctrl: (
          <FilterEditKebab
            key={`${item.pk}-kebab`}
            data={item}
            last_index={this.state.count}
            needUpdate={this.needUpdate}
            setExpand={this.setExpand}
          />
        ),
        expandedDescription,
      };
    });

    return (
      <div style={{ marginTop: 15 }}>
        <Helmet>
          <title>{`${STAMUS} - Policies`}</title>
        </Helmet>

        <Table
          style={{ marginTop: '10px', marginBottom: '10px' }}
          size="small"
          loading={this.state.loading}
          dataSource={dataSource}
          columns={this.columns}
          expandable={{
            columnWidth: 5,
            expandRowByClick: this.state.expand,
            expandedRowRender: item => (
              <ActionItem
                expandedDescription={item.expandedDescription}
                filters={item.filters}
                expandedRulesets={item.rulesets}
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
            itemsList={this.props.rules_list}
          />
        </ErrorHandler>
      </div>
    );
  }
}

ActionsPage.propTypes = {
  rules_list: PropTypes.any,
  updateListState: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
  multiTenancy: PropTypes.bool.isRequired,
};
