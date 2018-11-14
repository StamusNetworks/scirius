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
import { PAGINATION_VIEW, ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Modal, DropdownKebab, MenuItem, Icon, Button, Form, FormGroup, FormControl, Row, Col, Spinner } from 'patternfly-react';
import * as config from './config/Api';
import { HuntList, HuntPaginationRow } from './Api';
import { HuntRestError } from './Error';

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

// eslint-disable-next-line react/no-multi-comp
class FilterEditKebab extends React.Component {
    constructor(props) {
        super(props);
        this.displayToggle = this.displayToggle.bind(this);
        this.hideToggle = this.hideToggle.bind(this);
        this.state = { toggle: { show: false, action: 'delete' } };
        this.closeAction = this.closeAction.bind(this);
    }

    displayToggle(action) {
        this.setState({ toggle: { show: true, action } });
    }

    hideToggle() {
        this.setState({ toggle: { show: false, action: this.state.toggle.action } });
    }

    closeAction() {
        this.setState({ toggle: { show: false, action: 'delete' } });
    }

    render() {
        return (
            <React.Fragment>
                <DropdownKebab id="filterActions" pullRight>
                    {this.props.data.index !== 0 && <MenuItem onClick={() => { this.displayToggle('movetop'); }}>
                        Send Filter to top
                    </MenuItem>}
                    <MenuItem onClick={() => { this.displayToggle('move'); }}>
                        Move Filter
                    </MenuItem>
                    <MenuItem onClick={() => { this.displayToggle('movebottom'); }}>
                        Send Filter to bottom
                    </MenuItem>
                    <MenuItem divider />
                    <MenuItem onClick={() => { this.displayToggle('delete'); }}>
                        Delete Filter
                    </MenuItem>
                </DropdownKebab>
                <FilterToggleModal show={this.state.toggle.show} action={this.state.toggle.action} data={this.props.data} close={this.closeAction} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />
            </React.Fragment>
        );
    }
}
FilterEditKebab.propTypes = {
    data: PropTypes.any,
    last_index: PropTypes.any,
    needUpdate: PropTypes.any,
};

// eslint-disable-next-line react/no-multi-comp
class FilterToggleModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            comment: '',
            new_index: 0,
            errors: undefined
        };
        this.close = this.close.bind(this);
        this.submit = this.submit.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleCommentChange = this.handleCommentChange.bind(this);
        this.onFieldKeyPress = this.onFieldKeyPress.bind(this);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.action !== this.props.action) {
            // Move to top / Launch dialog init with 0, then event to update new_index
            // eslint-disable-next-line react/no-did-update-set-state
            this.setState({ new_index: 0 });

            if (this.props.action === 'movebottom') {
                // eslint-disable-next-line react/no-did-update-set-state
                this.setState({ new_index: this.props.last_index });
            }
        }
    }

    onFieldKeyPress(keyEvent) {
        if (keyEvent.key === 'Enter') {
            if (this.state.new_index < 0) {
                // Propagate event to trigger validation error
                return;
            }
            keyEvent.stopPropagation();
            keyEvent.preventDefault();
        }
    }

    handleChange(event) {
        const val = parseInt(event.target.value, 10);
        if (val >= 0) {
            this.setState({ new_index: val });
        }
    }

    handleCommentChange(event) {
        this.setState({ comment: event.target.value });
    }

    submit() {
        let data;
        if (['move', 'movetop', 'movebottom'].indexOf(this.props.action) !== -1) {
            data = { index: this.state.new_index, comment: this.state.comment };
            axios.patch(`${config.API_URL}${config.PROCESSING_PATH}${this.props.data.pk}/`, data).then(() => {
                this.props.needUpdate();
                this.close();
            }).catch((error) => {
                this.setState({ errors: error.response.data });
            });
        }
        if (this.props.action === 'delete') {
            data = { comment: this.state.comment };
            axios({
                url: `${config.API_URL}${config.PROCESSING_PATH}${this.props.data.pk}/`,
                data,
                method: 'delete'
            }).then(
                () => {
                    this.props.needUpdate();
                    this.close();
                }
            ).catch((error) => {
                this.setState({ errors: error.response.data });
            });
        }
    }

    close() {
        this.setState({ errors: undefined });
        this.props.close();
    }

    render() {
        let { action } = this.props;
        switch (action) {
            case 'movetop':
                action = 'Move to top';
                break;
            case 'move':
                action = 'Move';
                break;
            case 'movebottom':
                action = 'Move to bottom';
                break;
            case 'delete':
                action = 'Delete';
                break;
            default:
                break;
        }
        return (
            <Modal show={this.props.show} onHide={this.close}>
                <Modal.Header>
                    <button
                        className="close"
                        onClick={this.close}
                        aria-hidden="true"
                        aria-label="Close"
                    >
                        <Icon type="pf" name="close" />
                    </button>
                    {this.props.data && <Modal.Title>{action} {this.props.data.action} at current position {this.props.data.index}</Modal.Title>}
                </Modal.Header>
                <Modal.Body>
                    <HuntRestError errors={this.state.errors} />
                    <Form horizontal>
                        {this.props.action === 'move' && <FormGroup key="index" controlId="index" disabled={false}>
                            <Col sm={3}>
                                <strong>New index</strong>
                            </Col>
                            <Col sm={9}>
                                <FormControl type="number" min={0} max={50000} disabled={false} defaultValue={0} onChange={this.handleChange} onKeyPress={(e) => this.onFieldKeyPress(e)} />
                            </Col>
                        </FormGroup>
                        }
                        <div className="form-group">
                            <div className="col-sm-9">
                                <strong>Optional comment</strong>
                                <textarea value={this.state.comment} cols={70} onChange={this.handleCommentChange} />
                            </div>
                        </div>
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button
                        bsStyle="default"
                        className="btn-cancel"
                        onClick={this.close}
                    >
                        Cancel
                    </Button>
                    <Button bsStyle="primary" onClick={this.submit}>
                        Submit
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}
FilterToggleModal.propTypes = {
    action: PropTypes.any,
    last_index: PropTypes.any,
    data: PropTypes.any,
    show: PropTypes.any,
    close: PropTypes.func,
    needUpdate: PropTypes.func,
};
