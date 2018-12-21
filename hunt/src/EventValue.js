/* eslint-disable jsx-a11y/no-static-element-interactions */
import React from 'react';
import PropTypes from 'prop-types';
import { Icon } from 'patternfly-react';
import EventValueInfo from './EventValueInfo';

export default class EventValue extends React.Component {
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
