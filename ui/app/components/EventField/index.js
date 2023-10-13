import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';

const EventField = ({ value, field_name: fieldName, format, field }) => {
  if (value?.toString().length > 0) {
    return (
      <div data-test={`event-item-${fieldName}`} className="dl-item">
        <dt>{fieldName}</dt>
        <dd>
          <EventValue format={format} field={field} value={value} />
        </dd>
      </div>
    );
  }
  return null;
};

EventField.propTypes = {
  field_name: PropTypes.any,
  field: PropTypes.any,
  value: PropTypes.any,
  format: PropTypes.func,
};

export default EventField;
