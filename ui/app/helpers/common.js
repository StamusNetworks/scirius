import React from 'react';
import { Button, Dropdown, Menu } from 'antd';
import { DownOutlined } from '@ant-design/icons';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from 'hunt_common/buildQFilter';

export function actionsButtons() {
  if (process.env.REACT_APP_HAS_ACTION === '1' || process.env.NODE_ENV === 'development') {
    if (this.state.supported_actions.length === 0) {
      return (
        <div className="form-group">
          <Dropdown id="dropdown-basic-actions" overlay={null} trigger={['click']} disabled>
            <Button size="small">
              Policy Actions <DownOutlined />
            </Button>
          </Dropdown>
        </div>
      );
    }
    const actions = [];
    let eventKey = 1;
    for (let i = 0; i < this.state.supported_actions.length; i += 1) {
      const action = this.state.supported_actions[i];
      if (action[0] === '-') {
        actions.push(<hr key={`divider${i}`} />);
      } else {
        actions.push(
          <Menu.Item
            key={action[0]}
            eventKey={eventKey}
            onClick={() => {
              this.createAction(action[0]);
            }}
          >
            {action[1]}
          </Menu.Item>,
        );
        eventKey += 1;
      }
    }
    return (
      <div className="form-group">
        <Dropdown id="dropdown-basic-actions" overlay={<Menu>{actions}</Menu>} trigger={['click']}>
          <Button size="small">
            Policy Actions <DownOutlined />
          </Button>
        </Dropdown>
      </div>
    );
  }
  return null;
}

export function buildListUrlParams(pageParams) {
  const { page, perPage } = pageParams.pagination;
  const { sort } = pageParams;
  let ordering = '';

  if (sort.asc) {
    ordering = sort.id;
  } else {
    ordering = `-${sort.id}`;
  }

  return `ordering=${ordering}&page_size=${perPage}&page=${page}`;
}

export function loadActions(filtersIn) {
  let { filters } = this.props;
  if (typeof filtersIn !== 'undefined') {
    filters = filtersIn;
  }
  filters = filters.map((f) => f.id);
  const reqData = { fields: filters };
  axios.post(`${config.API_URL}${config.PROCESSING_PATH}test_actions/`, reqData).then((res) => {
    this.setState({ supported_actions: res.data.actions });
  });
}

export function createAction(type) {
  this.setState({ action: { view: true, type } });
}

export function closeAction() {
  this.setState({ action: { view: false, type: null } });
}

export function buildFilter(filters) {
  const lFilters = {};
  for (let i = 0; i < filters.length; i += 1) {
    if (filters[i].id !== 'probe' && filters[i].id !== 'alert.tag') {
      if (filters[i].id in lFilters) {
        lFilters[filters[i].id] += `,${filters[i].value}`;
      } else {
        lFilters[filters[i].id] = filters[i].value;
      }
    }
  }
  let stringFilters = '';
  const objKeys = Object.keys(lFilters);
  for (let k = 0; k < objKeys.length; k += 1) {
    stringFilters += `&${objKeys[k]}=${lFilters[objKeys[k]]}`;
  }
  const qfilter = buildQFilter(filters, this.props.systemSettings);
  if (qfilter) {
    stringFilters += qfilter;
  }
  return stringFilters;
}
