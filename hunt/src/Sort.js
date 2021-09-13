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
import { Button, Dropdown, Menu } from 'antd';
import { DownOutlined, SortAscendingOutlined, SortDescendingOutlined } from '@ant-design/icons';

export class HuntSort extends React.Component {
  constructor(props) {
    super(props);
    const activeSort = this.props.itemsList.sort;
    let sortType;
    for (let i = 0; i < this.props.config.length; i += 1) {
      if (activeSort.id === this.props.config[i].id) {
        sortType = this.props.config[i];
        break;
      }
    }
    if (sortType === undefined) {
      [sortType] = this.props.config;
    }
    this.state = {
      currentSortType: sortType,
      isSortAscending: activeSort.asc,
    };
    this.updateSort = this.updateSort.bind(this);
  }

  updateSort = (sort) => {
    this.props.itemsListUpdate({
      ...this.props.itemsList,
      sort: {
        ...this.props.itemsList.sort,
        ...sort,
      },
    });
  };

  updateCurrentSortType = (sortType) => {
    const { currentSortType } = this.state;
    if (currentSortType !== sortType) {
      this.setState({
        currentSortType: sortType,
        isSortAscending: sortType.defaultAsc,
      });
      this.updateSort({ id: sortType.id, asc: sortType.defaultAsc });
    }
  };

  toggleCurrentSortDirection = () => {
    this.updateSort({ id: this.state.currentSortType.id, asc: !this.state.isSortAscending });
    this.setState((prevState) => ({ isSortAscending: !prevState.isSortAscending }));
  };

  menu = () => (
    <Menu selectedKeys={[this.state.currentSortType.id]}>
      {this.props.config.map((conf) => (
        <Menu.Item
          key={conf.id}
          onClick={() => {
            this.updateCurrentSortType(conf);
          }}
        >
          {conf.title}
        </Menu.Item>
      ))}
    </Menu>
  );

  render() {
    const { currentSortType, isSortAscending } = this.state;
    return (
      <div>
        <Dropdown overlay={this.menu} trigger={['click']} disabled={this.props.disabled}>
          <Button size="small">
            {currentSortType.title} <DownOutlined />
          </Button>
        </Dropdown>
        <Button
          type="text"
          icon={isSortAscending ? <SortAscendingOutlined /> : <SortDescendingOutlined />}
          disabled={this.props.disabled}
          onClick={() => this.toggleCurrentSortDirection()}
        />
      </div>
    );
  }
}
HuntSort.propTypes = {
  config: PropTypes.any,
  itemsList: PropTypes.any,
  itemsListUpdate: PropTypes.any,
  disabled: PropTypes.any,
};
