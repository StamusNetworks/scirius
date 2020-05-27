/* eslint-disable react/no-unused-state */
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
import { ListView, Spinner } from 'patternfly-react';
import axios from 'axios';
import store from 'store';
import md5 from 'md5';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from 'hunt_common/buildQFilter';
import { buildFilterParams } from 'hunt_common/buildFilterParams';
import RuleToggleModal from 'hunt_common/RuleToggleModal';
import HuntFilter from '../../HuntFilter';
import AlertItem from '../../components/AlertItem';
import { actionsButtons, buildListUrlParams, loadActions, UpdateFilter, createAction, closeAction } from '../../helpers/common';
import ErrorHandler from '../../components/Error';
import HuntRestError from '../../components/HuntRestError';

export class AlertsPage extends React.Component {
    constructor(props) {
        super(props);

        const huntFilters = store.get('huntFilters');
        const rulesFilters = (typeof huntFilters !== 'undefined' && typeof huntFilters.alertslist !== 'undefined') ? huntFilters.alertslist.data : [];
        this.state = {
            alerts: [],
            rulesets: [],
            loading: true,
            refresh_data: false,
            action: { view: false, type: 'suppress' },
            net_error: undefined,
            rulesFilters,
            supported_actions: [],
            errors: null
        };
        this.fetchData = this.fetchData.bind(this);
        this.actionsButtons = actionsButtons.bind(this);
        this.buildListUrlParams = buildListUrlParams.bind(this);
        this.loadActions = loadActions.bind(this);
        this.UpdateFilter = UpdateFilter.bind(this);
        this.createAction = createAction.bind(this);
        this.closeAction = closeAction.bind(this);
    }

    componentDidMount() {
        this.fetchData(this.props.rules_list, this.props.filtersWithAlert);
        if (this.state.rulesets.length === 0) {
            axios.get(config.API_URL + config.RULESET_PATH).then((res) => {
                this.setState({ rulesets: res.data.results });
            });
        }
        const huntFilters = store.get('huntFilters');
        axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
            (res) => {
                const fdata = [];
                const keys = Object.keys(res.data);
                const values = Object.values(res.data);
                for (let i = 0; i < keys.length; i += 1) {
                    /* Only ES filter are allowed for Alert page */
                    if (['filter'].indexOf(values[i].queryType) !== -1) {
                        if (values[i].filterType !== 'hunt') {
                            fdata.push(values[i]);
                        }
                    }
                }
                const currentCheckSum = md5(JSON.stringify(fdata));
                if ((typeof huntFilters === 'undefined' || typeof huntFilters.alertslist === 'undefined') || huntFilters.alertslist.checkSum !== currentCheckSum) {
                    store.set('huntFilters', {
                        ...huntFilters,
                        alertslist: {
                            checkSum: currentCheckSum,
                            data: fdata
                        }
                    });
                    this.setState({ rulesFilters: fdata });
                }
            }
        );
        this.loadActions();
    }

    componentDidUpdate(prevProps) {
        const filtersChanged = (JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert));
        if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) || filtersChanged) {
            this.fetchData(this.props.rules_list, this.props.filtersWithAlert);
            if (filtersChanged) {
                this.loadActions();
            }
        }
    }

    fetchData(state, filters) {
        const stringFilters = buildQFilter(filters, this.props.systemSettings);
        const filterParams = buildFilterParams(this.props.filterParams);
        this.setState({ refresh_data: true, loading: true });

        const url = `${config.API_URL + config.ES_BASE_PATH}alerts_tail/?search_target=0&${this.buildListUrlParams(state)}&${filterParams}${stringFilters}`;
        axios.get(url)
        .then((res) => {
            if ((res.data !== null) && (typeof res.data !== 'string')) {
                this.setState({ alerts: res.data, loading: false, error: null });
            } else {
                this.setState({ loading: false });
            }
        })
        .catch((error) => {
            if (error.response.status === 500) {
                this.setState({ errors: [`${error.response.data[0].slice(0, 160)}...`], loading: false });
                return;
            }
            this.setState({ errors: null, loading: false });
        });
    }

    updateRuleListState(rulesListState) {
        this.props.updateListState(rulesListState);
    }

    render() {
        return (
            <div className="AlertsList HuntList">
                {this.state.errors && <HuntRestError errors={this.state.errors} />}
                <ErrorHandler>
                    <HuntFilter
                        config={this.props.rules_list}
                        ActiveSort={this.props.rules_list.sort}
                        UpdateSort={this.UpdateSort}
                        setViewType={this.setViewType}
                        filterFields={this.state.rulesFilters}
                        sort_config={undefined}
                        actionsButtons={this.actionsButtons}
                        queryType={['filter', 'filter_host_id']}
                        page={this.props.page}
                    />
                </ErrorHandler>
                <Spinner loading={this.state.loading}>
                </Spinner>
                <ListView>
                    {this.state.alerts.map((rule) => (
                        // eslint-disable-next-line no-underscore-dangle
                        <ErrorHandler key={rule._id}>
                            {/* eslint-disable-next-line no-underscore-dangle */}
                            <AlertItem key={rule._id} id={rule._id} data={rule._source} filterParams={this.props.filterParams} UpdateFilter={this.UpdateFilter} filters={this.props.filters} addFilter={this.props.addFilter} />
                        </ErrorHandler>
                    ))}
                </ListView>
                <ErrorHandler>
                    {this.state.action.view && <RuleToggleModal
                        show={this.state.action.view}
                        action={this.state.action.type}
                        config={this.props.rules_list}
                        filters={this.props.filters}
                        close={this.closeAction}
                        rulesets={this.state.rulesets}
                        systemSettings={this.props.systemSettings}
                        filterParams={this.props.filterParams}
                    />}
                </ErrorHandler>
            </div>
        );
    }
}

AlertsPage.propTypes = {
    rules_list: PropTypes.any,
    filters: PropTypes.any,
    filtersWithAlert: PropTypes.any,
    systemSettings: PropTypes.any,
    updateListState: PropTypes.any,
    page: PropTypes.any,
    addFilter: PropTypes.func,
    filterParams: PropTypes.object.isRequired
};
