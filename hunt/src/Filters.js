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
import { PAGINATION_VIEW, ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Spinner } from 'patternfly-react';
import * as config from './config/Api';
import { HuntList } from './Api';
import HuntPaginationRow from './HuntPaginationRow';
import FilterEditKebab from './FilterEditKebab';

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

class FilterItem extends React.Component {
    constructor(props) {
        super(props);
        // eslint-disable-next-line react/no-unused-state
        this.state = { data: undefined, loading: true };
    }

    componentDidMount() {
        this.fetchData(this.props.config, this.props.filters);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date) {
            this.fetchData(this.props.config, this.props.filters);
        }
    }

    // eslint-disable-next-line no-unused-vars
    fetchData(filtersStat, filters) {
        // eslint-disable-next-line react/no-unused-state
        this.setState({ loading: true });
        axios.get(`${config.API_URL + config.ES_BASE_PATH}poststats_summary&value=rule_filter_${this.props.data.pk}&from_date=${this.props.from_date}`)
        .then((res) => {
            // eslint-disable-next-line react/no-unused-state
            this.setState({ data: res.data, loading: false });
        }).catch(() => {
            // eslint-disable-next-line react/no-unused-state
            this.setState({ loading: false });
        });
    }

    render() {
        const item = this.props.data;
        const addinfo = [];
        for (let i = 0; i < item.filter_defs.length; i += 1) {
            const info = <ListViewInfoItem key={`filter-${i}`}><p>{item.filter_defs[i].operator === 'different' && 'Not '}{item.filter_defs[i].key}: {item.filter_defs[i].value}</p></ListViewInfoItem>;
            addinfo.push(info);
        }
        if (Object.keys(this.props.rulesets).length > 0) {
            const rulesets = item.rulesets.map((item2) => (<ListViewInfoItem key={`${item2}-ruleset`}><p>Ruleset: {this.props.rulesets[item2].name}</p></ListViewInfoItem>));
            addinfo.push(rulesets);
        }
        let description = '';
        if (item.action !== 'suppress') {
            description = <ul className="list-inline">{Object.keys(item.options).map((option) => (<li key={option}><strong>{option}</strong>: {item.options[option]}</li>))}</ul>;
        }
        let icon;
        switch (item.action) {
            case 'suppress':
                icon = <ListViewIcon name="close" />;
                break;
            case 'threshold':
                icon = <ListViewIcon name="minus" />;
                break;
            case 'tag':
                icon = <ListViewIcon name="envelope" />;
                break;
            case 'tagkeep':
                icon = <ListViewIcon name="envelope" />;
                break;
            default:
                icon = <ListViewIcon name="envelope" />;
                break;
        }
        const actionsMenu = [<span key={`${item.pk}-index`} className="badge badge-default">{item.index}</span>];
        actionsMenu.push(<FilterEditKebab key={`${item.pk}-kebab`} data={item} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />);
        return (
            <ListViewItem
                key={`${item.pk}-listitem`}
                leftContent={icon}
                additionalInfo={addinfo}
                heading={item.action}
                description={description}
                actions={actionsMenu}
            >
                {this.state.data && <Row>
                    {this.state.data.map((item2) => (
                        <div className="col-xs-3 col-sm-2 col-md-2" key={item2.key}>
                            <div className="card-pf card-pf-accented card-pf-aggregate-status">
                                <h2 className="card-pf-title">
                                    <span className="fa fa-shield" />{item2.key}
                                </h2>
                                <div className="card-pf-body">
                                    <p className="card-pf-aggregate-status-notifications">
                                        <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-ok" />{item2.seen.value}</span>
                                        <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-error-circle-o" />{item2.drop.value}</span>
                                    </p>
                                </div>
                            </div>
                        </div>
                    ))
                    }
                </Row>}
            </ListViewItem>
        );
    }
}
FilterItem.propTypes = {
    config: PropTypes.any,
    data: PropTypes.any,
    filters: PropTypes.any,
    from_date: PropTypes.any,
    rulesets: PropTypes.any,
    needUpdate: PropTypes.any,
    last_index: PropTypes.any,
};
