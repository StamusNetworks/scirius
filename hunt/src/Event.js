/* eslint-disable jsx-a11y/click-events-have-key-events,jsx-a11y/interactive-supports-focus,jsx-a11y/no-static-element-interactions */
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
import axios from 'axios';
import { Icon, Modal, Button, Row } from 'patternfly-react';
import PropTypes from 'prop-types';
import EventIPResolver from './EventIPResolver';
import EventIPPastries from './EventIPPastries';
import EventIPGeoloc from './EventIPGeoloc';
import EventIPThreatlist from './EventIPThreatlist';
import EventIPSynscan from './EventIPSynscan';
import EventIPDatascan from './EventIPDatascan';

// eslint-disable-next-line react/prefer-stateless-function
export class EventField extends React.Component {
    render() {
        return (
            <React.Fragment>
                <dt>{this.props.field_name}</dt>
                <dd>
                    <EventValue field={this.props.field} value={this.props.value} addFilter={this.props.addFilter} />
                </dd>
            </React.Fragment>
        );
    }
}
EventField.propTypes = {
    field_name: PropTypes.any,
    addFilter: PropTypes.any,
    field: PropTypes.any,
    value: PropTypes.any,
};

// eslint-disable-next-line react/no-multi-comp
class EventIPInfo extends React.Component {
    constructor(props) {
        super(props);
        this.state = { ipinfo: null, show_ip_info: false };
        this.displayIPInfo = this.displayIPInfo.bind(this);
        this.closeIPInfo = this.closeIPInfo.bind(this);
    }

    closeIPInfo() {
        this.setState({ show_ip_info: false });
    }

    displayIPInfo() {
        this.setState({ show_ip_info: true });
        if (this.state.ipinfo === null) {
            axios.get(`https://www.onyphe.io/api/ip/${this.props.value}?apikey=${process.env.REACT_APP_ONYPHE_API_KEY}`).then(
                (res) => {
                    this.setState({ ipinfo: res.data.results });
                }
            );
        }
    }

    render() {
        const pastries = [];
        const resolvers = [];
        if (this.state.ipinfo) {
            this.state.ipinfo.map((item) => {
                if (item['@category'] === 'pastries') {
                    pastries.push(item);
                }
                if (item['@category'] === 'resolver') {
                    resolvers.push(item);
                }
                return 1;
            });
        }
        return (
            <React.Fragment>
                <a onClick={this.displayIPInfo} role={'button'}> <Icon type="fa" name="info-circle" /></a>
                <Modal show={this.state.show_ip_info} onHide={this.closeIPInfo}>
                    <Modal.Header>
                        <button
                            className="close"
                            onClick={this.closeIPInfo}
                            aria-hidden="true"
                            aria-label="Close"
                        >
                            <Icon type="pf" name="close" />
                        </button>
                        <Modal.Title>
                            Some Info from <a href={`https://www.onyphe.io/search/?query=${this.props.value}`} target="_blank">Onyphe.io for {this.props.value}</a>
                        </Modal.Title>
                    </Modal.Header>
                    <Modal.Body>
                        {this.state.ipinfo && <Row>
                            {this.state.ipinfo.map((item) => {
                                if (item['@category'] === 'geoloc') {
                                    return (<EventIPGeoloc data={item} />);
                                }
                                if (item['@category'] === 'datascan') {
                                    return (<EventIPDatascan data={item} />);
                                }
                                if (item['@category'] === 'synscan') {
                                    return (<EventIPSynscan data={item} />);
                                }
                                if (item['@category'] === 'threatlist') {
                                    return (<EventIPThreatlist data={item} />);
                                }

                                return null;
                            })}
                            {resolvers.length > 0 && <EventIPResolver data={resolvers} />}
                            {pastries.length > 0 && <EventIPPastries data={pastries} />}
                        </Row>}
                        {this.state.ipinfo === null && <p>Fetching IP info</p>}
                    </Modal.Body>
                    <Modal.Footer>
                        <Button
                            bsStyle="default"
                            className="btn-cancel"
                            onClick={this.closeIPInfo}
                        >Close
                        </Button>
                    </Modal.Footer>
                </Modal>
            </React.Fragment>
        );
    }
}
EventIPInfo.propTypes = {
    value: PropTypes.any,
};

// eslint-disable-next-line react/prefer-stateless-function,react/no-multi-comp
class EventValueInfo extends React.Component {
    render() {
        if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(this.props.field) > -1) {
            if (process.env.REACT_APP_ONYPHE_API_KEY) {
                return (<EventIPInfo value={this.props.value} />);
            }
            return (
                <a href={`https://www.onyphe.io/search/?query=${this.props.value}`} target="_blank"> <Icon type="fa" name="info-circle" /></a>
            );
        }
        return null;
    }
}
EventValueInfo.propTypes = {
    value: PropTypes.any,
    field: PropTypes.any,
};

// eslint-disable-next-line react/no-multi-comp
export class EventValue extends React.Component {
    constructor(props) {
        super(props);
        this.state = { display_actions: false };
    }

    render() {
        const valueText = this.props.value;
        return (
            // eslint-disable-next-line jsx-a11y/mouse-events-have-key-events
            <div
                onMouseOver={() => { this.setState({ display_actions: true }); }}
                onMouseOut={() => { this.setState({ display_actions: false }); }}
                className="value-field-complete"
            >
                <span className="value-field" title={valueText}>{valueText}</span>
                <span className={this.state.display_actions ? 'eventFilters value-actions' : 'eventFiltersHidden value-actions'}>
                    <EventValueInfo field={this.props.field} value={this.props.value} />
                    <a onClick={() => { this.props.addFilter(this.props.field, this.props.value, false); }}> <Icon type="fa" name="search-plus" /></a>
                    <a onClick={() => { this.props.addFilter(this.props.field, this.props.value, true); }}> <Icon type="fa" name="search-minus" /></a>
                </span>
                {this.props.right_info && <span className="value-right-info">{this.props.right_info}</span>}
            </div>
        );
    }
}
EventValue.propTypes = {
    addFilter: PropTypes.any,
    right_info: PropTypes.any,
    field: PropTypes.any,
    value: PropTypes.any,
};
