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
import { Icon } from 'patternfly-react';
import PropTypes from 'prop-types';
import EventValueInfo from './EventValueInfo';

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
