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
import { Drawer, Dropdown, Input, Menu, Spin } from 'antd';
import { BellOutlined, DashboardOutlined, IdcardOutlined, InfoCircleOutlined, MenuOutlined, SafetyOutlined, UploadOutlined } from '@ant-design/icons';
import { sections, huntUrls } from 'ui/constants';
import { compose } from 'redux';
import { connect } from 'react-redux';
import { reload } from '../../containers/HuntApp/stores/filterParams';
import history from '../../utils/history';

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

  getIcons = item => {
    const icons = [];
    if (item.page === 'DASHBOARDS') {
      icons.push(<DashboardOutlined key="0" />);
    }
    if (item.page === 'RULES_LIST') {
      icons.push(<SafetyOutlined key="1" />);
    }
    if (item.page === 'ALERTS_LIST') {
      icons.push(<BellOutlined key="2" />);
    }
    if (item.page === 'HOSTS_LIST') {
      icons.push(<IdcardOutlined key="3" />);
    }

    if (item.imported) {
      icons.push(<UploadOutlined key="4" />);
    }
    return icons;
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

    history.push(`/stamus/${huntUrls[row.page]}`);
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
        <Menu defaultOpenKeys={[this.state.expandedPanel]} mode="inline">
          <Menu.SubMenu
            key="global"
            onTitleClick={() => this.togglePanel(globaL)}
            title={
              <div style={{ lineHeight: '20px' }}>
                <div className={this.state.expandedPanel === globaL ? '' : 'collapsed'}>Global Filter Sets</div>
                <div>{`${rowsGlobal ? rowsGlobal.length : 0} Filter Sets`}</div>
              </div>
            }
          >
            {this.props.loading && (
              <Menu.Item key="1">
                <Spin>Loading more</Spin>
              </Menu.Item>
            )}
            {rowsGlobal &&
              rowsGlobal.map(item => (
                <Menu.Item
                  key={item.id}
                  style={{ height: '100%' }}
                  onClick={() => this.props.deleteFilterSet('global', item)}
                  title={item.description}
                >
                  <div id={globaL}>
                    <div key="containsNotifications">
                      {this.getIcons(item)}

                      <span>
                        <b>{item.name}</b>
                      </span>
                      <Dropdown
                        id="Dropdown1"
                        overlay={
                          <Menu>
                            <Menu.Item key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </Menu.Item>
                            {!noRights && (
                              <Menu.Item key="delete" onClick={() => this.props.deleteFilterSet('global', item)}>
                                Delete
                              </Menu.Item>
                            )}
                          </Menu>
                        }
                        trigger={['click']}
                      >
                        <a className="ant-dropdown-link" onClick={e => e.preventDefault()}>
                          <MenuOutlined />
                        </a>
                      </Dropdown>
                      <div>
                        <span>{`${item.pageTitle} Page | `}</span>
                        <span>Shared</span>
                      </div>
                    </div>
                    {!rowsGlobal && <InfoCircleOutlined />}
                  </div>
                </Menu.Item>
              ))}
          </Menu.SubMenu>
          <Menu.SubMenu
            key="private"
            onTitleClick={() => this.togglePanel(privatE)}
            title={
              <div style={{ lineHeight: '20px' }}>
                <div className={this.state.expandedPanel === privatE ? '' : 'collapsed'}>Private Filter Sets</div>
                <div>{`${rowsPrivate ? rowsPrivate.length : 0} Filter Sets`}</div>
              </div>
            }
          >
            {this.props.loading && (
              <Menu.Item key="2">
                <Spin>Loading more</Spin>
              </Menu.Item>
            )}
            {rowsPrivate &&
              rowsPrivate.map(item => (
                <Menu.Item
                  key={item.id}
                  style={{ height: '100%' }}
                  onClick={() => this.props.deleteFilterSet('private', item)}
                  title={item.description}
                >
                  <div id={privatE}>
                    <div key="containsNotifications">
                      {this.getIcons(item)}

                      <span>
                        <b>{item.name}</b>
                      </span>
                      <Dropdown
                        id="Dropdown2"
                        overlay={
                          <Menu>
                            <Menu.Item key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </Menu.Item>
                            <Menu.Item key="delete" onClick={() => this.props.deleteFilterSet('private', item)}>
                              Delete
                            </Menu.Item>
                          </Menu>
                        }
                        trigger={['click']}
                      >
                        <a className="ant-dropdown-link" onClick={e => e.preventDefault()}>
                          <MenuOutlined />
                        </a>
                      </Dropdown>
                      <div>
                        <span>{`${item.pageTitle} Page | `}</span>
                        <span>Private</span>
                      </div>
                    </div>
                    {!rowsPrivate && <InfoCircleOutlined />}
                  </div>
                </Menu.Item>
              ))}
          </Menu.SubMenu>
          <Menu.SubMenu
            key="static"
            onTitleClick={() => this.togglePanel(statiC)}
            title={
              <div style={{ lineHeight: '20px' }}>
                <div className={this.state.expandedPanel === statiC ? '' : 'collapsed'}>Stamus Predefined Filter Sets</div>
                <div>{`${rowsStatic ? rowsStatic.length : 0} Filter Sets`}</div>
              </div>
            }
          >
            {this.props.loading && (
              <Menu.Item key="3">
                <Spin>Loading more</Spin>
              </Menu.Item>
            )}
            {rowsStatic &&
              rowsStatic.map(item => (
                <Menu.Item key={item.id} style={{ height: '100%' }} onClick={() => this.loadFilterSets(item)} title={item.description}>
                  <div id={statiC}>
                    <div key="containsNotifications">
                      {this.getIcons(item)}
                      <span>
                        <b>{item.name}</b>
                      </span>
                      <Dropdown
                        id="Dropdown3"
                        overlay={
                          <Menu>
                            <Menu.Item key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </Menu.Item>
                          </Menu>
                        }
                        trigger={['click']}
                      >
                        <a className="ant-dropdown-link" onClick={e => e.preventDefault()}>
                          <MenuOutlined />
                        </a>
                      </Dropdown>
                      <div>
                        <span>{`${item.pageTitle} Page | `}</span>
                        <span>Static</span>
                      </div>
                    </div>
                    {!rowsStatic && <InfoCircleOutlined />}
                  </div>
                </Menu.Item>
              ))}
          </Menu.SubMenu>
        </Menu>
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

const mapDispatchToProps = dispatch => ({
  reload: () => dispatch(reload()),
});

const withConnect = connect(null, mapDispatchToProps);

export default compose(withConnect)(FilterSets);
