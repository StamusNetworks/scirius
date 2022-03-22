import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';

const EventField = (props) =>
  props.value && props.value.toString().length > 0 ? (
    <div className="dl-item">
      <dt>{props.field_name}</dt>
      <dd>
        <EventValue format={props.format} field={props.field} value={props.value} magnifiers={props.magnifiers} addFilter={props.addFilter} />
      </dd>
    </div>
  ) : null;

EventField.defaultProps = {
  magnifiers: true,
};

EventField.propTypes = {
  field_name: PropTypes.any,
  addFilter: PropTypes.any,
  field: PropTypes.any,
  value: PropTypes.any,
  magnifiers: PropTypes.bool,
  format: PropTypes.func,
};

export default EventField;
