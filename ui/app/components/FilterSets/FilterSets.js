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
import styled from 'styled-components';
import { Drawer, Input, Spin, Collapse } from 'antd';
import { sections, huntUrls } from 'ui/constants';
import FilterSetList from 'ui/components/FilterSetList';
import { bindActionCreators, compose } from 'redux';
import { connect } from 'react-redux';
import actions from 'ui/containers/App/actions';
import history from '../../utils/history';

const Panel = styled(Collapse.Panel)`
  .ant-collapse-content-box {
    padding: 0;
  }
`;

class FilterSets extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      expandedPanel: 'static',
      searchValue: '',
    };

    this.escFunction = this.escFunction.bind(this);
  }

  componentDidMount() {
    this.props.loadFilterSets();
    document.addEventListener('keydown', this.escFunction, false);
  }

  componentWillUnmount() {
    document.removeEventListener('keydown', this.escFunction, false);
  }

  togglePanel = key => {
    if (this.state.expandedPanel === key) this.setState({ expandedPanel: false });
    else this.setState({ expandedPanel: key });
  };

  handleSearchValue = event => {
    this.setState({ searchValue: event.target.value });
  };

  escFunction(event) {
    const esc = 27;

    if (event.keyCode === esc) {
      this.props.close();
    }
  }

  loadFilterSets(row) {
    this.props.clearFilters(sections.GLOBAL);

    const filters = row.content.filter(f => f.id !== 'alert.tag');
    this.props.addFilter(sections.GLOBAL, filters);

    if (process.env.REACT_APP_HAS_TAG) {
      const alertTag = row.content.filter(f => f.id === 'alert.tag')[0];
      this.props.setTag(alertTag);
    }

    const { search } = window.location;
    history.push(`/stamus/${huntUrls[row.page]}${search}`);
    this.props.reload();
  }

  render() {
    const globaL = 'global';
    const privatE = 'private';
    const statiC = 'static';
    const rowsGlobal = this.props.globalSet
      ? this.props.globalSet.filter(item => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const rowsPrivate = this.props.privateSet
      ? this.props.privateSet.filter(item => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const rowsStatic = this.props.staticSet
      ? this.props.staticSet.filter(item => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const noRights = this.props.user.isActive && !this.props.user.permissions.includes('rules.events_edit');

    return (
      <Drawer visible onClose={() => this.props.close()} title={<div>Filter Sets</div>} placement="right" zIndex={10000} width={450} size="large">
        <div>
          <div className="input-group">
            <span className="input-group-addon">
              <i className="fa fa-search"></i>
            </span>
            <Input value={this.state.searchValue} onChange={this.handleSearchValue} />
          </div>
        </div>
        <Collapse defaultOpenKeys={[this.state.expandedPanel]} mode="inline">
          <Panel
            key="global"
            onTitleClick={() => this.togglePanel(globaL)}
            header={<span className={this.state.expandedPanel === globaL ? '' : 'collapsed'}>Global Filter Sets</span>}
            extra={`${rowsGlobal ? rowsGlobal.length : 0} Filter Sets`}
          >
            {this.props.loading && <Spin>Loading more</Spin>}
            {rowsGlobal &&
              rowsGlobal.map(item => (
                <FilterSetList
                  item={item}
                  loadFilterSets={() => this.loadFilterSets(item)}
                  deleteFilterSet={() => this.props.deleteFilterSet('global', item)}
                  info={rowsGlobal}
                  noRights={noRights}
                />
              ))}
          </Panel>
          <Panel
            key="private"
            onTitleClick={() => this.togglePanel(privatE)}
            header={<span className={this.state.expandedPanel === privatE ? '' : 'collapsed'}>Private Filter Sets</span>}
            extra={<span>{`${rowsPrivate ? rowsPrivate.length : 0} Filter Sets`}</span>}
          >
            {this.props.loading && <Spin>Loading more</Spin>}
            {rowsPrivate &&
              rowsPrivate.map(item => (
                <FilterSetList
                  item={item}
                  loadFilterSets={() => this.loadFilterSets(item)}
                  deleteFilterSet={() => this.props.deleteFilterSet('private', item)}
                  info={rowsPrivate}
                  noRights={noRights}
                />
              ))}
          </Panel>
          <Panel
            key="static"
            onTitleClick={() => this.togglePanel(statiC)}
            header={<span className={this.state.expandedPanel === statiC ? '' : 'collapsed'}>Stamus Predefined Filter Sets</span>}
            extra={<span>{`${rowsStatic ? rowsStatic.length : 0} Filter Sets`}</span>}
          >
            {this.props.loading && <Spin>Loading more</Spin>}
            {rowsStatic &&
              rowsStatic.map(item => (
                <FilterSetList item={item} loadFilterSets={() => this.loadFilterSets(item)} info={rowsStatic} noRights={noRights} />
              ))}
          </Panel>
        </Collapse>
      </Drawer>
    );
  }
}

FilterSets.propTypes = {
  close: PropTypes.any,
  reload: PropTypes.any,
  addFilter: PropTypes.func,
  clearFilters: PropTypes.func,
  loading: PropTypes.bool,
  loadFilterSets: PropTypes.func,
  deleteFilterSet: PropTypes.func,
  globalSet: PropTypes.array,
  privateSet: PropTypes.array,
  staticSet: PropTypes.array,
  setTag: PropTypes.func,
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

const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      reload: actions.doReload,
    },
    dispatch,
  );

const withConnect = connect(null, mapDispatchToProps);

export default compose(withConnect)(FilterSets);
