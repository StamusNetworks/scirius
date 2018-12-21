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
import * as config from './config/Api';
import { HuntList } from './HuntList';
import HuntPaginationRow from './HuntPaginationRow';
import FilterItem from './FilterItem';

export class FiltersList extends HuntList {
    constructor(props) {
        super(props);
        this.state = { data: [], count: 0, rulesets: [] };
        this.fetchData = this.fetchData.bind(this);
        this.needUpdate = this.needUpdate.bind(this);
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
        this.fetchData(this.props.config, this.props.filters);
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
        this.fetchData(this.props.config, this.props.filters);
    }

    render() {
        return (
            <div>
                <Spinner loading={this.state.loading}></Spinner>
                <ListView>
                    {this.state.data && this.state.data.map((item) => (
                        <FilterItem key={item.pk} data={item} switchPage={this.props.switchPage} last_index={this.state.count} needUpdate={this.needUpdate} rulesets={this.state.rulesets} from_date={this.props.from_date} />
                    ))}
                </ListView>
                <HuntPaginationRow
                    viewType={PAGINATION_VIEW.LIST}
                    pagination={this.props.config.pagination}
                    onPaginationChange={this.handlePaginationChange}
                    amountOfPages={Math.ceil(this.state.count / this.props.config.pagination.perPage)}
                    pageInputValue={this.props.config.pagination.page}
                    itemCount={this.state.count - 1} // used as last item
                    itemsStart={(this.props.config.pagination.page - 1) * this.props.config.pagination.perPage}
                    itemsEnd={Math.min((this.props.config.pagination.page * this.props.config.pagination.perPage) - 1, this.state.count - 1)}
                    onFirstPage={this.onFirstPage}
                    onNextPage={this.onNextPage}
                    onPreviousPage={this.onPrevPage}
                    onLastPage={this.onLastPage}

                />

            </div>
        );
    }
}
FiltersList.propTypes = {
    config: PropTypes.any,
    filters: PropTypes.any,
};
