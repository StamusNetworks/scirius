import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';
import Filter from 'ui/utils/Filter';

const EventField = ({ filter }) => {
  if (!filter.value) return null;
  return (
    <div data-test={`event-item-${filter.instance.title}`} className="dl-item">
      <dt>{filter.instance.title}</dt>
      <dd>
        <EventValue filter={filter} />
      </dd>
    </div>
  );
};

EventField.propTypes = {
  filter: PropTypes.instanceOf(Filter),
};

export default EventField;
