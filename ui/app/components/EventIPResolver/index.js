import React from 'react';

import PropTypes from 'prop-types';

const EventIPResolver = props => (
  <div>
    <h4>Resolver info</h4>
    <dl>
      {props.data.map(item => {
        let value = 'unknown';
        if (item.type === 'forward') {
          value = item.forward;
        }
        if (item.type === 'reverse') {
          value = item.reverse;
        }
        return (
          <React.Fragment key={`${value}-${item.seen_date}`}>
            <dt>{item.type}</dt>
            <dd>
              {value} ({item.seen_date})
            </dd>
          </React.Fragment>
        );
      })}
    </dl>
  </div>
);

EventIPResolver.propTypes = {
  data: PropTypes.any,
};

export default EventIPResolver;
