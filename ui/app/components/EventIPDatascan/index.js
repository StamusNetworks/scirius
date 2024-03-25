import React from 'react';

import PropTypes from 'prop-types';

const EventIPDatascan = props => (
  <div>
    <h4>Data scanner result</h4>
    <dl>
      {props.data.product && (
        <React.Fragment>
          <dt>Product</dt>
          <dd>{props.data.product}</dd>
        </React.Fragment>
      )}
      {props.data.productversion && (
        <React.Fragment>
          <dt>Version</dt>
          <dd>{props.data.productversion}</dd>
        </React.Fragment>
      )}
      {props.data.port && (
        <React.Fragment>
          <dt>Port</dt>
          <dd>{props.data.port}</dd>
        </React.Fragment>
      )}
      {props.data.data && (
        <React.Fragment>
          <dt>Data</dt>
          <dd>{props.data.data.substring(0, 200)}</dd>
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

EventIPDatascan.propTypes = {
  data: PropTypes.any,
};

export default EventIPDatascan;
