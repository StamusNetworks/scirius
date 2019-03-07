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
import { buildQFilter } from '../../helpers/buildQFilter';
import RuleToggleModal from '../../RuleToggleModal';
import { HuntFilter } from '../../HuntFilter';
import AlertItem from '../../components/AlertItem';
import { actionsButtons, buildListUrlParams, loadActions, UpdateFilter, addFilter, createAction, closeAction } from '../../helpers/common';
import ErrorHandler from '../../components/Error';

export default class AlertsPage extends React.Component {
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
            supported_actions: []
        };
        this.fetchData = this.fetchData.bind(this);
        this.actionsButtons = actionsButtons.bind(this);
        this.buildListUrlParams = buildListUrlParams.bind(this);
        this.loadActions = loadActions.bind(this);
        this.UpdateFilter = UpdateFilter.bind(this);
        this.addFilter = addFilter.bind(this);
        this.createAction = createAction.bind(this);
        this.closeAction = closeAction.bind(this);
    }

    componentDidMount() {
        this.fetchData(this.props.rules_list, this.props.filters);
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
        if (prevProps.from_date !== this.props.from_date) {
            this.fetchData(this.props.rules_list, this.props.filters);
        }
    }

    fetchData(state, filters) {
        let stringFilters = buildQFilter(filters, this.props.systemSettings);
        if (stringFilters === null) {
            stringFilters = '';
        } else {
            stringFilters = `&filter=${stringFilters.replace('&qfilter=', '')}`;
        }
        this.setState({ refresh_data: true, loading: true });
        const url = `${config.API_URL + config.ES_BASE_PATH}alerts_tail&search_target=0&${this.buildListUrlParams(state)}&from_date=${this.props.from_date}${stringFilters}`;
        axios.get(url).then((res) => {
            if ((res.data !== null) && (typeof res.data !== 'string')) {
                this.setState({ alerts: res.data, loading: false });
            } else {
                this.setState({ loading: false });
            }
        });
    }

    updateRuleListState(rulesListState) {
        this.props.updateListState(rulesListState);
    }

    render() {
        return (
            <div className="AlertsList HuntList">
                <ErrorHandler>
                    <HuntFilter
                        ActiveFilters={this.props.filters}
                        config={this.props.rules_list}
                        ActiveSort={this.props.rules_list.sort}
                        UpdateFilter={this.UpdateFilter}
                        UpdateSort={this.UpdateSort}
                        setViewType={this.setViewType}
                        filterFields={this.state.rulesFilters}
                        sort_config={undefined}
                        displayToggle={this.state.display_toggle}
                        actionsButtons={this.actionsButtons}
                        queryType={['filter']}
                    />
                </ErrorHandler>
                <Spinner loading={this.state.loading}>
                </Spinner>
                <ListView>
                    {this.state.alerts.map((rule) => (
                        // eslint-disable-next-line no-underscore-dangle
                        <ErrorHandler key={rule._id}>
                            {/* eslint-disable-next-line no-underscore-dangle */}
                            <AlertItem key={rule._id} id={rule._id} data={rule._source} from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} filters={this.props.filters} addFilter={this.addFilter} />
                        </ErrorHandler>
                    ))}
                </ListView>
                <ErrorHandler>
                    <RuleToggleModal
                        show={this.state.action.view}
                        action={this.state.action.type}
                        config={this.props.rules_list}
                        filters={this.props.filters}
                        close={this.closeAction}
                        rulesets={this.state.rulesets}
                    />
                </ErrorHandler>
            </div>
        );
    }
}

AlertsPage.propTypes = {
    rules_list: PropTypes.any,
    filters: PropTypes.any,
    from_date: PropTypes.any,
    systemSettings: PropTypes.any,
    updateListState: PropTypes.any,
};
