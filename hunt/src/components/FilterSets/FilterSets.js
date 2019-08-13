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
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { sections } from '../../containers/App/stores/global';

export default class FilterSets extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            expandedPanel: 'static',
            searchValue: '',
            user: undefined
        };

        this.escFunction = this.escFunction.bind(this);
    }

    componentDidMount() {
        axios.get(`${config.API_URL}${config.USER_PATH}current_user/`)
        .then((currentUser) => {
            this.setState({ user: currentUser.data });
        });

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
    }

    getIcon = (item) => {
        if (item.page === 'DASHBOARDS') {
            return <Icon className="pull-left" type="fa" name="tachometer" />;
        }
        if (item.page === 'RULES_LIST') {
            return <Icon className="pull-left" type="pf" name="security" />;
        }
        if (item.page === 'ALERTS_LIST') {
            return <Icon className="pull-left" type="fa" name="bell" />;
        }
        if (item.page === 'HOSTS_LIST') {
            return <Icon className="pull-left" type="fa" name="id-card-o" />;
        }
        return undefined;
    }

    escFunction(event) {
        const esc = 27;

        if (event.keyCode === esc) {
            this.props.close();
        }
    }

    loadFilterSets(row) {
        this.props.clearFilters(sections.GLOBAL);
        this.props.addFilter(sections.GLOBAL, row.content);
        this.props.switchPage(row.page);
        this.props.reload();
    }

    render() {
        const globaL = 'global';
        const privatE = 'private';
        const statiC = 'static';
        const rowsGlobal = this.props.globalSet ? this.props.globalSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase())) : [];
        const rowsPrivate = this.props.privateSet ? this.props.privateSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase())) : [];
        const rowsStatic = this.props.staticSet ? this.props.staticSet.filter((item) => item.name.toLowerCase().includes(this.state.searchValue.toLowerCase())) : [];
        const noRights = this.state.user !== undefined && this.state.user.is_active && !this.state.user.is_staff && !this.state.user.is_superuser;

        return (
            <NotificationDrawer>
                <NotificationDrawer.Title onCloseClick={() => this.props.close()} title={'Filter Sets'} expandable={false} />
                <FormGroup controlId="text">
                    <div className="input-group">
                        <span className="input-group-addon"><i className="fa fa-search"></i></span>
                        <FormControl
                            type="text"
                            disabled={false}
                            value={this.state.searchValue}
                            onChange={this.handleSearchValue}
                        />
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
                                {rowsGlobal && <NotificationDrawer.PanelBody key="containsNotifications">

                                    {rowsGlobal.map((item) => (
                                        <span key={item.name} data-toggle="tooltip" title={item.description}>
                                            <Notification key={item.id} seen={false}>
                                                <NotificationDrawer.Dropdown id="Dropdown1">
                                                    <MenuItem key={'load'} onClick={() => this.loadFilterSets(item)}>Load</MenuItem>
                                                    {!noRights && <MenuItem key={'delete'} onClick={() => this.props.deleteFilterSet('global', item)}>Delete</MenuItem>}
                                                </NotificationDrawer.Dropdown>
                                                {this.getIcon(item)}
                                                <Notification.Content onClick={() => this.loadFilterSets(item)}>
                                                    <Notification.Message>
                                                        {item.name}
                                                    </Notification.Message>
                                                    <Notification.Info leftText={`${item.pageTitle} Page`} rightText={'Shared'} />
                                                </Notification.Content>
                                            </Notification>
                                        </span>
                                    ))}
                                    {this.props.loading && <Notification key="loading" type="loading" />}
                                </NotificationDrawer.PanelBody>
                                }
                                {!rowsGlobal && <NotificationDrawer.EmptyState title={''} />}

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
                                {rowsPrivate && <NotificationDrawer.PanelBody key="containsNotifications">

                                    {rowsPrivate.map((item) => (
                                        <span key={item.name} data-toggle="tooltip" title={item.description}>
                                            <Notification key={item.id} seen={false}>
                                                <NotificationDrawer.Dropdown id="Dropdown2">
                                                    <MenuItem key={'load'} onClick={() => this.loadFilterSets(item)}>Load</MenuItem>
                                                    <MenuItem key={'delete'} onClick={() => this.props.deleteFilterSet('private', item)}>Delete</MenuItem>
                                                </NotificationDrawer.Dropdown>
                                                {this.getIcon(item)}
                                                <Notification.Content onClick={() => this.loadFilterSets(item)}>
                                                    <Notification.Message>
                                                        {item.name}
                                                    </Notification.Message>
                                                    <Notification.Info leftText={`${item.pageTitle} Page`} rightText={'Private'} />
                                                </Notification.Content>
                                            </Notification>
                                        </span>
                                    ))}
                                    {this.props.loading && <Notification key="loading" type="loading" />}

                                </NotificationDrawer.PanelBody>
                                }
                                {!rowsPrivate && <NotificationDrawer.EmptyState title={''} />}

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
                                {rowsStatic && <NotificationDrawer.PanelBody key="containsNotifications">

                                    {rowsStatic.map((item) => (
                                        <span key={item.name} data-toggle="tooltip" title={item.description}>
                                            <Notification key={item.id} seen={false}>
                                                <NotificationDrawer.Dropdown id="Dropdown3">
                                                    <MenuItem key={'load'} onClick={() => this.loadFilterSets(item)}>Load</MenuItem>
                                                </NotificationDrawer.Dropdown>
                                                {this.getIcon(item)}
                                                <Notification.Content onClick={() => this.loadFilterSets(item)}>
                                                    <Notification.Message>
                                                        {item.name}
                                                    </Notification.Message>
                                                    <Notification.Info leftText={`${item.pageTitle} Page`} rightText={'Static'} />
                                                </Notification.Content>
                                            </Notification>
                                        </span>
                                    ))}
                                    {this.props.loading && <Notification key="loading" type="loading" />}

                                </NotificationDrawer.PanelBody>
                                }
                                {!rowsPrivate && <NotificationDrawer.EmptyState title={''} />}

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
};
