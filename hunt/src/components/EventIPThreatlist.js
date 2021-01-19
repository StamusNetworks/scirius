import React from 'react';
import PropTypes from 'prop-types';
import { Col } from 'patternfly-react';

const EventIPThreatlist = (props) => (
  <Col md={6}>
    <h4>Threat list info</h4>
    <dl>
      {props.data['@type'] && (
        <React.Fragment>
          <dt>Type</dt>
          <dd>{props.data['@type']}</dd>
        </React.Fragment>
      )}
      {props.data.threatlist && (
        <React.Fragment>
          <dt>Threat list</dt>
          <dd>{props.data.threatlist}</dd>
        </React.Fragment>
      )}
      {props.data.subnet && (
        <React.Fragment>
          <dt>Subnet</dt>
          <dd>{props.data.subnet}</dd>
        </React.Fragment>
      )}
      {props.data.seen_date && (
        <React.Fragment>
          <dt>Seen date</dt>
          <dd>{props.data.seen_date}</dd>
        </React.Fragment>
      )}
    </dl>
  </Col>
);

EventIPThreatlist.propTypes = {
  data: PropTypes.any,
};

export default EventIPThreatlist;
