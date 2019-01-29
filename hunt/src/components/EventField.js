import React from 'react';
import PropTypes from 'prop-types';
import EventValue from './EventValue';

const EventField = (props) => (
    <React.Fragment>
        <dt>{props.field_name}</dt>
        <dd>
            <EventValue field={props.field} value={props.value} magnifiers={props.magnifiers} addFilter={props.addFilter} />
        </dd>
    </React.Fragment>
);

EventField.defaultProps = {
    magnifiers: true,
}

EventField.propTypes = {
    field_name: PropTypes.any,
    addFilter: PropTypes.any,
    field: PropTypes.any,
    value: PropTypes.any,
    magnifiers: PropTypes.bool,
};

export default EventField;
