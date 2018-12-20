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
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Icon, Spinner, PAGINATION_VIEW, Row, Col } from 'patternfly-react';
import axios from 'axios';
import { HuntFilter } from './Filter';
import { HuntList } from './Api';
import HuntPaginationRow from './HuntPaginationRow';
import * as config from './config/Api';
import { PAGE_STATE } from './Const';

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


export class HistoryPage extends HuntList {
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

    componentDidMount() {
        this.fetchData(this.props.config, this.props.filters);
        axios.get(`${config.API_URL}${config.HISTORY_PATH}get_action_type_list/`).then(
            (res) => {
                const filterFields = Object.assign([], this.state.filterFields);
                let actions;
                for (let field = 0; field < filterFields.length; field += 1) {
                    if (filterFields[field].id !== 'action_type') {
                        // eslint-disable-next-line no-continue
                        continue;
                    }
                    actions = filterFields[field];
                    break;
                }
                actions.filterValues = [];
                const actionTypeList = Object.keys(res.data.action_type_list);
                for (let i = 0; i < actionTypeList.length; i += 1) {
                    const item = actionTypeList[i];
                    actions.filterValues.push({ id: item, title: res.data.action_type_list[item] });
                }
                this.setState({ ...this.state, filterFields });
            }
        );
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
                <HuntFilter ActiveFilters={this.props.filters}
                    config={this.props.config}
                    ActiveSort={this.props.config.sort}
                    UpdateFilter={this.UpdateFilter}
                    UpdateSort={this.UpdateSort}
                    setViewType={this.setViewType}
                    filterFields={this.state.filterFields}
                    sort_config={HistorySortFields}
                    displayToggle={false}
                    queryType={['all']}
                    got_alert_tag={false}
                />
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
HistoryPage.propTypes = {
    config: PropTypes.any,
    filters: PropTypes.any,
    switchPage: PropTypes.any,
};

// eslint-disable-next-line react/prefer-stateless-function
class HistoryItem extends React.Component {
    render() {
        const date = new Date(Date.parse(this.props.data.date)).toLocaleString('en-GB', { timeZone: 'UTC' });
        const info = [<ListViewInfoItem key="date"><p>Date: {date}</p></ListViewInfoItem>,
            <ListViewInfoItem key="user"><p><Icon type="pf" name="user" /> {this.props.data.username}</p>
            </ListViewInfoItem>
        ];
        if (this.props.data.ua_objects.ruleset && this.props.data.ua_objects.ruleset.pk) {
            info.push(<ListViewInfoItem key="ruleset"><p><Icon type="fa" name="th" /> {this.props.data.ua_objects.ruleset.value}</p></ListViewInfoItem>);
        }
        if (this.props.data.ua_objects.rule && this.props.data.ua_objects.rule.sid) {
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
            info.push(<ListViewInfoItem key="rule"><p><a onClick={() => this.props.switchPage(PAGE_STATE.rules_list, this.props.data.ua_objects.rule.sid)}><Icon type="fa" name="bell" /> {this.props.data.ua_objects.rule.sid}</a></p></ListViewInfoItem>);
        }
        return (
            <ListViewItem
                leftContent={<ListViewIcon name="envelope" />}
                additionalInfo={info}
                heading={this.props.data.title}
                description={this.props.data.description}
                key={this.props.data.pk}
                compoundExpand={this.props.expand_row}
                compoundExpanded
            >
                {this.props.data.comment && <Row>
                    <Col sm={11}>
                        <div className="container-fluid">
                            <strong>Comment</strong>
                            <p>{this.props.data.comment}</p>
                        </div>
                    </Col>
                </Row>}
            </ListViewItem>
        );
    }
}
HistoryItem.propTypes = {
    data: PropTypes.any,
    switchPage: PropTypes.any,
    expand_row: PropTypes.any,
};
