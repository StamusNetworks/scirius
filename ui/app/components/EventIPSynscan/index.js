import React from 'react';

import PropTypes from 'prop-types';

const EventIPSynscan = props => (
  <div>
    <h4>SYN scanner result</h4>
    <dl>
      {props.data.os && (
        <React.Fragment>
          <dt>Operating System</dt>
          <dd>{props.data.os}</dd>
        </React.Fragment>
      )}
      {props.data.port && (
        <React.Fragment>
          <dt>Port</dt>
          <dd>{props.data.port}</dd>
        </React.Fragment>
      )}
      {props.data.seen_date && (
        <React.Fragment>
          <dt>Seen date</dt>
          <dd>{props.data.seen_date}</dd>
        </React.Fragment>
      )}
    </dl>
  </div>
);

EventIPSynscan.propTypes = {
  data: PropTypes.any,
};

export default EventIPSynscan;
