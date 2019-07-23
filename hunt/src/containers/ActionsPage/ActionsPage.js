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
import { PAGINATION_VIEW, ListView, Spinner } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import HuntPaginationRow from '../../HuntPaginationRow';
import FilterItem from '../../FilterItem';
import ErrorHandler from '../../components/Error';
import { actionsButtons,
    buildListUrlParams,
    loadActions,
    createAction,
    UpdateFilter,
    handlePaginationChange,
    onFirstPage,
    onNextPage,
    onPrevPage,
    onLastPage,
    setViewType,
    UpdateSort,
    closeAction,
    updateAlertTag,
    buildFilter } from '../../helpers/common';

export default class ActionsPage extends React.Component {
    constructor(props) {
        super(props);
        this.handlePaginationChange = handlePaginationChange.bind(this);
        this.onFirstPage = onFirstPage.bind(this);
        this.onNextPage = onNextPage.bind(this);
        this.onPrevPage = onPrevPage.bind(this);
        this.onLastPage = onLastPage.bind(this);
        this.UpdateFilter = UpdateFilter.bind(this);
        this.UpdateSort = UpdateSort.bind(this);

        this.buildFilter = buildFilter.bind(this);

        this.setViewType = setViewType.bind(this);

        this.actionsButtons = actionsButtons.bind(this);
        this.createAction = createAction.bind(this);
        this.closeAction = closeAction.bind(this);
        this.loadActions = loadActions.bind(this);

        this.updateAlertTag = updateAlertTag.bind(this);
        this.state = { data: [], count: 0, rulesets: [] };
        this.fetchData = this.fetchData.bind(this);
        this.needUpdate = this.needUpdate.bind(this);
        this.buildListUrlParams = buildListUrlParams.bind(this);
    }

    componentDidMount() {
        if (this.state.rulesets.length === 0) {
            axios.get(`${config.API_URL}${config.RULESET_PATH}`).then((res) => {
                const rulesets = {};
                for (let index = 0; index < res.data.results.length; index += 1) {
                    rulesets[res.data.results[index].pk] = res.data.results[index];
                }
                this.setState({ rulesets });
            });
        }
        this.fetchData(this.props.rules_list, this.props.filters);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date || JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)) {
            this.fetchData(this.props.rules_list, this.props.filters);
        }
    }

    updateRuleListState(rulesListState) {
        this.props.updateListState(rulesListState);
    }

    // eslint-disable-next-line no-unused-vars
    fetchData(filtersStat, filters) {
        this.setState({ loading: true });
        axios.get(`${config.API_URL}${config.PROCESSING_PATH}?${this.buildListUrlParams(filtersStat)}`)
        .then((res) => {
            this.setState({ data: res.data.results, count: res.data.count, loading: false });
        }).catch(() => {
            this.setState({ loading: false });
        });
    }

    needUpdate() {
        this.fetchData(this.props.rules_list, this.props.filters);
    }

    render() {
        return (
            <div>
                <Spinner loading={this.state.loading}></Spinner>
                <ListView>
                    {this.state.data && this.state.data.map((item) => (
                        <FilterItem key={item.pk} data={item} updateIDSFilterState={this.props.updateIDSFilterState} last_index={this.state.count} needUpdate={this.needUpdate} rulesets={this.state.rulesets} from_date={this.props.from_date} />
                    ))}
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
ActionsPage.propTypes = {
    rules_list: PropTypes.any,
    filters: PropTypes.any,
    updateListState: PropTypes.func,
    updateIDSFilterState: PropTypes.func,
    from_date: PropTypes.any,
};
