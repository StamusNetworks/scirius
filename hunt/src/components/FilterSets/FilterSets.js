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
import { FormGroup, FormControl, Notification, NotificationDrawer, MenuItem, Icon } from 'patternfly-react';
import { Collapse } from 'react-bootstrap';
import { sections } from 'hunt_common/constants';

export default class FilterSets extends React.Component {
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

  togglePanel = (key) => {
    if (this.state.expandedPanel === key) this.setState({ expandedPanel: false });
    else this.setState({ expandedPanel: key });
  };

  handleSearchValue = (event) => {
    this.setState({ searchValue: event.target.value });
  };

  getIcons = (item) => {
    const icons = [];
    if (item.page === 'DASHBOARDS') {
      icons.push(<Icon className="pull-left" type="fa" name="tachometer" key="tachometer" />);
    }
    if (item.page === 'RULES_LIST') {
      icons.push(<Icon className="pull-left" type="pf" name="security" key="security" />);
    }
    if (item.page === 'ALERTS_LIST') {
      icons.push(<Icon className="pull-left" type="fa" name="bell" key="bell" />);
    }
    if (item.page === 'HOSTS_LIST') {
      icons.push(<Icon className="pull-left" type="fa" name="id-card-o" key="card" />);
    }

    if (item.imported) {
      icons.push(<Icon className="glyphicon-upload pull-right" title="Imported" key="upload" name="upload" />);
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

    const filters = row.content.filter((f) => f.id !== 'alert.tag');
    this.props.addFilter(sections.GLOBAL, filters);

    if (process.env.REACT_APP_HAS_TAG) {
      const alertTag = row.content.filter((f) => f.id === 'alert.tag')[0];
      this.props.setTag(alertTag);
    }

    this.props.switchPage(row.page);
    this.props.reload();
  }

  render() {
    const globaL = 'global';
    const privatE = 'private';
    const statiC = 'static';
    const rowsGlobal = this.props.globalSet
      ? this.props.globalSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const rowsPrivate = this.props.privateSet
      ? this.props.privateSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const rowsStatic = this.props.staticSet
      ? this.props.staticSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase()))
      : [];
    const noRights = this.props.user.isActive && !this.props.user.permissions.includes('rules.events_edit');

    return (
      <NotificationDrawer>
        <NotificationDrawer.Title onCloseClick={() => this.props.close()} title="Filter Sets" expandable={false} />
        <FormGroup controlId="text">
          <div className="input-group">
            <span className="input-group-addon">
              <i className="fa fa-search"></i>
            </span>
            <FormControl type="text" disabled={false} value={this.state.searchValue} onChange={this.handleSearchValue} />
          </div>
        </FormGroup>

        <NotificationDrawer.Accordion>
          <NotificationDrawer.Panel expanded={this.state.expandedPanel === globaL}>
            <NotificationDrawer.PanelHeading onClick={() => this.togglePanel(globaL)}>
              <NotificationDrawer.PanelTitle>
                <a className={this.state.expandedPanel === globaL ? '' : 'collapsed'}>Global Filter Sets</a>
              </NotificationDrawer.PanelTitle>
              <NotificationDrawer.PanelCounter text={`${rowsGlobal ? rowsGlobal.length : 0} Filter Sets`} />
            </NotificationDrawer.PanelHeading>

            <Collapse in={this.state.expandedPanel === globaL}>
              <NotificationDrawer.PanelCollapse id={globaL}>
                {rowsGlobal && (
                  <NotificationDrawer.PanelBody key="containsNotifications">
                    {rowsGlobal.map((item) => (
                      <span key={Math.random()} data-toggle="tooltip" title={item.description}>
                        <Notification key={item.id} seen={false}>
                          <NotificationDrawer.Dropdown id="Dropdown1">
                            <MenuItem key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </MenuItem>
                            {!noRights && (
                              <MenuItem key="delete" onClick={() => this.props.deleteFilterSet('global', item)}>
                                Delete
                              </MenuItem>
                            )}
                          </NotificationDrawer.Dropdown>
                          {this.getIcons(item)}
                          <Notification.Content onClick={() => this.loadFilterSets(item)}>
                            <Notification.Message>{item.name}</Notification.Message>
                            <Notification.Info leftText={`${item.pageTitle} Page`} rightText="Shared" />
                          </Notification.Content>
                        </Notification>
                      </span>
                    ))}
                    {this.props.loading && <Notification key="loading" type="loading" />}
                  </NotificationDrawer.PanelBody>
                )}
                {!rowsGlobal && <NotificationDrawer.EmptyState title="" />}
              </NotificationDrawer.PanelCollapse>
            </Collapse>
          </NotificationDrawer.Panel>
          <NotificationDrawer.Panel expanded={this.state.expandedPanel === privatE}>
            <NotificationDrawer.PanelHeading onClick={() => this.togglePanel(privatE)}>
              <NotificationDrawer.PanelTitle>
                <a className={this.state.expandedPanel === privatE ? '' : 'collapsed'}>Private Filter Sets</a>
              </NotificationDrawer.PanelTitle>
              <NotificationDrawer.PanelCounter text={`${rowsPrivate ? rowsPrivate.length : 0} Filter Sets`} />
            </NotificationDrawer.PanelHeading>

            <Collapse in={this.state.expandedPanel === privatE}>
              <NotificationDrawer.PanelCollapse id={privatE}>
                {rowsPrivate && (
                  <NotificationDrawer.PanelBody key="containsNotifications">
                    {rowsPrivate.map((item) => (
                      <span key={item.name} data-toggle="tooltip" title={item.description}>
                        <Notification key={item.id} seen={false}>
                          <NotificationDrawer.Dropdown id="Dropdown2">
                            <MenuItem key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </MenuItem>
                            <MenuItem key="delete" onClick={() => this.props.deleteFilterSet('private', item)}>
                              Delete
                            </MenuItem>
                          </NotificationDrawer.Dropdown>
                          {this.getIcons(item)}
                          <Notification.Content onClick={() => this.loadFilterSets(item)}>
                            <Notification.Message>{item.name}</Notification.Message>
                            <Notification.Info leftText={`${item.pageTitle} Page`} rightText="Private" />
                          </Notification.Content>
                        </Notification>
                      </span>
                    ))}
                    {this.props.loading && <Notification key="loading" type="loading" />}
                  </NotificationDrawer.PanelBody>
                )}
                {!rowsPrivate && <NotificationDrawer.EmptyState title="" />}
              </NotificationDrawer.PanelCollapse>
            </Collapse>
          </NotificationDrawer.Panel>

          <NotificationDrawer.Panel expanded={this.state.expandedPanel === statiC}>
            <NotificationDrawer.PanelHeading onClick={() => this.togglePanel(statiC)}>
              <NotificationDrawer.PanelTitle>
                <a className={this.state.expandedPanel === statiC ? '' : 'collapsed'}>Stamus Predefined Filter Sets</a>
              </NotificationDrawer.PanelTitle>
              <NotificationDrawer.PanelCounter text={`${rowsStatic ? rowsStatic.length : 0} Filter Sets`} />
            </NotificationDrawer.PanelHeading>

            <Collapse in={this.state.expandedPanel === statiC}>
              <NotificationDrawer.PanelCollapse id={statiC}>
                {rowsStatic && (
                  <NotificationDrawer.PanelBody key="containsNotifications">
                    {rowsStatic.map((item) => (
                      <span key={item.name} data-toggle="tooltip" title={item.description}>
                        <Notification key={item.id} seen={false}>
                          <NotificationDrawer.Dropdown id="Dropdown3">
                            <MenuItem key="load" onClick={() => this.loadFilterSets(item)}>
                              Load
                            </MenuItem>
                          </NotificationDrawer.Dropdown>
                          {this.getIcons(item)}
                          <Notification.Content onClick={() => this.loadFilterSets(item)}>
                            <Notification.Message>{item.name}</Notification.Message>
                            <Notification.Info leftText={`${item.pageTitle} Page`} rightText="Static" />
                          </Notification.Content>
                        </Notification>
                      </span>
                    ))}
                    {this.props.loading && <Notification key="loading" type="loading" />}
                  </NotificationDrawer.PanelBody>
                )}
                {!rowsPrivate && <NotificationDrawer.EmptyState title="" />}
              </NotificationDrawer.PanelCollapse>
            </Collapse>
          </NotificationDrawer.Panel>
        </NotificationDrawer.Accordion>
      </NotificationDrawer>
    );
  }
}

FilterSets.propTypes = {
  switchPage: PropTypes.any,
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
