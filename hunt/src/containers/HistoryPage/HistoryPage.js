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
import { ListView, Spinner, PAGINATION_VIEW } from 'patternfly-react';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { HuntFilter } from '../../HuntFilter';
import HistoryItem from '../../components/HistoryItem';
import HuntPaginationRow from '../../HuntPaginationRow';
import ErrorHandler from '../../components/Error';
import { buildFilter, buildListUrlParams, UpdateFilter, loadActions, UpdateSort, onFirstPage, onNextPage, onPrevPage, onLastPage, handlePaginationChange } from '../../helpers/common';

const HistorySortFields = [
    {
        id: 'date',
        title: 'Date',
        isNumeric: true,
        defaultAsc: false,
    },
    {
        id: 'username',
        title: 'User',
        isNumeric: false,
        defaultAsc: false,
    }
];


export default class HistoryPage extends React.Component {
    constructor(props) {
        super(props);
        const HistoryFilterFields = [
            {
                id: 'username',
                title: 'User',
                placeholder: 'Filter by User',
                filterType: 'text',
                queryType: 'all'
            }, {
                id: 'comment',
                title: 'Comment',
                placeholder: 'Filter by Comment',
                filterType: 'text',
                queryType: 'all'
            }, {
                id: 'action_type',
                title: 'Action Type',
                placeholder: 'Filter by Action Type',
                filterType: 'select',
                filterValues: [],
                queryType: 'all'
            }
        ];
        this.state = { data: [], count: 0, filterFields: HistoryFilterFields };
        this.fetchData = this.fetchData.bind(this);
        this.buildFilter = buildFilter;
        this.buildListUrlParams = buildListUrlParams.bind(this);
        this.UpdateFilter = UpdateFilter.bind(this);
        this.loadActions = loadActions.bind(this);
        this.UpdateSort = UpdateSort.bind(this);
        this.onFirstPage = onFirstPage.bind(this);
        this.onNextPage = onNextPage.bind(this);
        this.onPrevPage = onPrevPage.bind(this);
        this.onLastPage = onLastPage.bind(this);
        this.handlePaginationChange = handlePaginationChange.bind(this);

        this.props.getActionTypes();
    }

    componentDidMount() {
        this.fetchData(this.props.rules_list, this.props.filters);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date) {
            this.fetchData(this.props.rules_list, this.props.filters);
        }
        if (prevProps.actionTypesList.length !== this.props.actionTypesList.length) {
            const filterFields = [...this.state.filterFields];
            filterFields.find((field) => field.id === 'action_type').filterValues = this.props.actionTypesList;
            // eslint-disable-next-line react/no-did-update-set-state
            this.setState({
                ...this.state,
                filterFields
            });
        }
    }

    fetchData(historyStat, filters) {
        const stringFilters = this.buildFilter(filters);
        this.setState({ refresh_data: true, loading: true });
        axios.get(`${config.API_URL}${config.HISTORY_PATH}?${this.buildListUrlParams(historyStat)}${stringFilters}`)
        .then((res) => {
            this.setState({
                data: res.data, count: res.data.count, refresh_data: false, loading: false
            });
        }).catch(() => {
            this.setState({ refresh_data: false, loading: false });
        });
    }

    updateRuleListState(rulesListState) {
        this.props.updateListState(rulesListState);
    }

    render() {
        let expand = false;
        for (let filter = 0; filter < this.props.filters; filter += 1) {
            if (this.props.filters[filter].id === 'comment') {
                expand = true;
                break;
            }
        }
        return (
            <div className="HistoryList HuntList">
                <ErrorHandler>
                    <HuntFilter ActiveFilters={this.props.filters}
                        config={this.props.rules_list}
                        ActiveSort={this.props.rules_list.sort}
                        UpdateFilter={this.UpdateFilter}
                        UpdateSort={this.UpdateSort}
                        setViewType={this.setViewType}
                        filterFields={this.state.filterFields}
                        sort_config={HistorySortFields}
                        displayToggle={false}
                        queryType={['all']}
                        got_alert_tag={false}
                        page={this.props.page}
                    />
                </ErrorHandler>
                <Spinner loading={this.state.loading}>
                </Spinner>
                <ListView>
                    {this.state.data.results && this.state.data.results.map((item) => (<HistoryItem key={item.pk}
                        data={item}
                        switchPage={this.props.switchPage}
                        expand_row={expand}
                    />))
                    }
                </ListView>
                <ErrorHandler>
                    <HuntPaginationRow
                        viewType={PAGINATION_VIEW.LIST}
                        pagination={this.props.rules_list.pagination}
                        onPaginationChange={this.handlePaginationChange}
                        amountOfPages={Math.ceil(this.state.count / this.props.rules_list.pagination.perPage)}
                        pageInputValue={this.props.rules_list.pagination.page}
                        itemCount={this.state.count - 1} // used as last item
                        itemsStart={(this.props.rules_list.pagination.page - 1) * this.props.rules_list.pagination.perPage}
                        itemsEnd={Math.min((this.props.rules_list.pagination.page * this.props.rules_list.pagination.perPage) - 1, this.state.count - 1)}
                        onFirstPage={this.onFirstPage}
                        onNextPage={this.onNextPage}
                        onPreviousPage={this.onPrevPage}
                        onLastPage={this.onLastPage}
                    />
                </ErrorHandler>
            </div>
        );
    }
}

HistoryPage.propTypes = {
    rules_list: PropTypes.any,
    filters: PropTypes.any,
    switchPage: PropTypes.any,
    from_date: PropTypes.any,
    updateListState: PropTypes.any,
    getActionTypes: PropTypes.func,
    actionTypesList: PropTypes.array,
    page: PropTypes.any
};
