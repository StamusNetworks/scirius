/* eslint-disable class-methods-use-this,react/sort-comp */
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
import { DropdownButton, MenuItem } from 'patternfly-react';
import * as config from './config/Api';

export class HuntList extends React.Component {
    constructor(props) {
        super(props);
        this.buildListUrlParams = this.buildListUrlParams.bind(this);
        this.fetchData = this.fetchData.bind(this);
        this.handlePaginationChange = this.handlePaginationChange.bind(this);
        this.onFirstPage = this.onFirstPage.bind(this);
        this.onNextPage = this.onNextPage.bind(this);
        this.onPrevPage = this.onPrevPage.bind(this);
        this.onLastPage = this.onLastPage.bind(this);
        this.UpdateFilter = this.UpdateFilter.bind(this);
        this.UpdateSort = this.UpdateSort.bind(this);

        this.buildFilter = this.buildFilter.bind(this);

        this.setViewType = this.setViewType.bind(this);

        this.actionsButtons = this.actionsButtons.bind(this);
        this.createAction = this.createAction.bind(this);
        this.closeAction = this.closeAction.bind(this);
        this.loadActions = this.loadActions.bind(this);

        this.updateAlertTag = this.updateAlertTag.bind(this);
    }

    componentDidMount() {
        this.fetchData(this.props.config, this.props.filters);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date) {
            this.fetchData(this.props.config, this.props.filters);
        }
    }

    onFirstPage() {
        const newListState = Object.assign({}, this.props.config);
        newListState.pagination.page = 1;
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    onNextPage() {
        const newListState = Object.assign({}, this.props.config);
        newListState.pagination.page += 1;
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    onPrevPage() {
        const newListState = Object.assign({}, this.props.config);
        newListState.pagination.page -= 1;
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    onLastPage() {
        const newListState = Object.assign({}, this.props.config);
        newListState.pagination.page = Math.ceil(this.state.count / this.props.config.pagination.perPage);
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    setViewType(type) {
        const newListState = Object.assign({}, this.props.config);
        newListState.view_type = type;
        this.props.updateListState(newListState);
    }

    // eslint-disable-next-line no-unused-vars,class-methods-use-this
    fetchData(state, filters) {}

    loadActions(filtersIn) {
        let { filters } = this.props;
        if (typeof filtersIn !== 'undefined') {
            filters = filtersIn;
        }
        filters = filters.map((f) => f.id);
        const reqData = { fields: filters };
        axios.post(`${config.API_URL}${config.PROCESSING_PATH}test_actions/`, reqData).then(
            (res) => {
                this.setState({ supported_actions: res.data.actions });
            });
    }

    createAction(type) {
        // eslint-disable-next-line react/no-unused-state
        this.setState({ action: { view: true, type } });
    }

    closeAction() {
        // eslint-disable-next-line react/no-unused-state
        this.setState({ action: { view: false, type: null } });
    }

    actionsButtons() {
        if (process.env.REACT_APP_HAS_ACTION === '1' || process.env.NODE_ENV === 'development') {
            if (this.state.supported_actions.length === 0) {
                return (
                    <div className="form-group">
                        <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions" disabled />
                    </div>
                );
            }
            const actions = [];
            let eventKey = 1;
            for (let i = 0; i < this.state.supported_actions.length; i += 1) {
                const action = this.state.supported_actions[i];
                if (action[0] === '-') {
                    actions.push(<MenuItem key={`divider${i}`} divider />);
                } else {
                    actions.push(
                        <MenuItem
                            key={action[0]}
                            eventKey={eventKey}
                            onClick={() => {
                                this.createAction(action[0]);
                            }}
                        >{action[1]}
                        </MenuItem>);
                    eventKey += 1;
                }
            }
            return (
                <div className="form-group">
                    <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions">
                        {actions}
                    </DropdownButton>
                </div>
            );
        }
        return null;
    }

    handlePaginationChange(pagin) {
        const lastPage = Math.ceil(this.state.count / pagin.perPage);
        if (pagin.page > lastPage) {
            pagin.page = lastPage;
        }

        const newListState = Object.assign({}, this.props.config);
        newListState.pagination = pagin;
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    addFilter = (field, value, negated) => {
        if (field !== 'alert.tag') {
            let filterText = '';
            filterText = field;
            filterText += ': ';
            filterText += value;
            const activeFilters = [...this.props.filters, {
                label: filterText, id: field, value, negated
            }];
            this.UpdateFilter(activeFilters);
        } else {
            let tfilters = {};
            if (negated) {
                tfilters = { untagged: true, informational: true, relevant: true };
                tfilters[value] = false;
            } else {
                tfilters = { untagged: false, informational: false, relevant: false };
                tfilters[value] = true;
            }
            this.updateAlertTag(tfilters);
        }
    }

    updateAlertTag(tfilters) {
        /* Update the filters on alert.tag and send the update */
        const activeFilters = Object.assign([], this.props.filters);
        const tagFilters = { id: 'alert.tag', value: tfilters };
        if (activeFilters.length === 0) {
            activeFilters.push(tagFilters);
        } else {
            let updated = false;
            for (let i = 0; i < activeFilters.length; i += 1) {
                if (activeFilters[i].id === 'alert.tag') {
                    activeFilters[i] = tagFilters;
                    updated = true;
                    break;
                }
            }
            if (updated === false) {
                activeFilters.push(tagFilters);
            }
        }
        this.UpdateFilter(activeFilters);
    }

    buildFilter(filters) {
        const lFilters = {};
        for (let i = 0; i < filters.length; i += 1) {
            if (filters[i].id in lFilters) {
                lFilters[filters[i].id] += `,${filters[i].value}`;
            } else {
                lFilters[filters[i].id] = filters[i].value;
            }
        }
        let stringFilters = '';
        const keys = Object.keys(lFilters);
        const values = Object.values(lFilters);
        for (let k = 0; k < keys.length; k += 1) {
            stringFilters += `&${keys[k]}=${values[k]}`;
        }
        return stringFilters;
    }

    UpdateFilter(filters, page = 1) {
        const newListState = Object.assign({}, this.props.config);
        newListState.pagination.page = page;
        this.props.updateFilterState(filters);
        this.props.updateListState(newListState);
        this.fetchData(newListState, filters);
        if (this.props.needReload) {
            this.props.needReload();
        }
        this.loadActions(filters);
    }

    UpdateSort(sort) {
        const newListState = Object.assign({}, this.props.config);
        newListState.sort = sort;
        this.props.updateListState(newListState);
        this.fetchData(newListState, this.props.filters);
    }

    // eslint-disable-next-line class-methods-use-this
    buildListUrlParams(pageParams) {
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
}
HuntList.propTypes = {
    config: PropTypes.any,
    filters: PropTypes.any,
    from_date: PropTypes.any,
    needReload: PropTypes.func,
    updateListState: PropTypes.func,
    updateFilterState: PropTypes.func,
};
