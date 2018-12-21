import React from 'react';
import PropTypes from 'prop-types';
import { EventValue } from './Event';

const EventField = (props) => (
    <React.Fragment>
        <dt>{props.field_name}</dt>
        <dd>
            <EventValue field={props.field} value={props.value} addFilter={props.addFilter} />
        </dd>
    </React.Fragment>
);

EventField.propTypes = {
    field_name: PropTypes.any,
    addFilter: PropTypes.any,
    field: PropTypes.any,
    value: PropTypes.any,
};

export default EventField;
