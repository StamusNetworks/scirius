import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';
import Filter from 'ui/utils/Filter';

const EventsField = ({ filters }) => {
  if (filters.length === 0 || filters.every(f => typeof f === 'undefined')) return null;

  return (
    <div data-test={`event-item-${filters[0].title}`} className="dl-item">
      <dt>{filters[0].title}</dt>
      <dd>
        {filters.map(filter => (
          <EventValue key={filter.displayValue} filter={filter} />
        ))}
      </dd>
    </div>
  );
};

EventsField.propTypes = {
  filters: PropTypes.arrayOf(PropTypes.instanceOf(Filter)),
};

export default EventsField;
