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
import ActionItem from '../../ActionItem';
import ErrorHandler from '../../components/Error';
import { actionsButtons,
    buildListUrlParams,
    loadActions,
    createAction,
    closeAction,
    buildFilter } from '../../helpers/common';

export class ActionsPage extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: [], count: 0, rulesets: [] };

        this.buildFilter = buildFilter.bind(this);
        this.actionsButtons = actionsButtons.bind(this);
        this.createAction = createAction.bind(this);
        this.closeAction = closeAction.bind(this);
        this.loadActions = loadActions.bind(this);
        this.fetchData = this.fetchData.bind(this);
        this.needUpdate = this.needUpdate.bind(this);
        this.buildListUrlParams = buildListUrlParams.bind(this);
        this.updateActionListState = this.updateActionListState.bind(this);
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
        this.fetchData();
    }

    componentDidUpdate(prevProps) {
        if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams)) {
            this.fetchData();
        }
    }

    updateActionListState(rulesListState) {
        this.props.updateListState(rulesListState, () => this.fetchData());
    }

    // eslint-disable-next-line no-unused-vars
    fetchData() {
        const listParams = this.buildListUrlParams(this.props.rules_list);
        this.setState({ loading: true });
        axios.get(`${config.API_URL}${config.PROCESSING_PATH}?${listParams}`)
        .then((res) => {
            this.setState({ data: res.data.results, count: res.data.count, loading: false });
        }).catch(() => {
            this.setState({ loading: false });
        });
    }

    needUpdate() {
        this.fetchData();
    }

    render() {
        return (
            <div>
                <Spinner loading={this.state.loading}></Spinner>
                <ListView>
                    {this.state.data && this.state.data.map((item) => (
                        <ActionItem switchPage={this.props.switchPage} key={item.pk} data={item} last_index={this.state.count} needUpdate={this.needUpdate} rulesets={this.state.rulesets} filterParams={this.props.filterParams} />
                    ))}
                </ListView>
                <ErrorHandler>
                    <HuntPaginationRow
                        viewType={PAGINATION_VIEW.LIST}
                        onPaginationChange={this.updateActionListState}
                        itemsCount={this.state.count}
                        itemsList={this.props.rules_list}
                    />
                </ErrorHandler>
            </div>
        );
    }
}

ActionsPage.propTypes = {
    rules_list: PropTypes.any,
    updateListState: PropTypes.func,
    switchPage: PropTypes.any,
    filterParams: PropTypes.object.isRequired
};
