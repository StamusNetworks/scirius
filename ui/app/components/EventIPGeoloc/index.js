import React from 'react';
import PropTypes from 'prop-types';

const EventIPGeoloc = props => (
  <div>
    <h4>Geo localization result</h4>
    <dl>
      <dt>Country</dt>
      <dd>{props.data.country}</dd>
      {props.data.city && (
        <React.Fragment>
          <dt>City</dt>
          <dd>{props.data.city}</dd>
        </React.Fragment>
      )}
      <dt>Organization</dt>
      <dd>{props.data.organization}</dd>
      <dt>ASN</dt>
      <dd>{props.data.asn}</dd>
      <dt>Subnet</dt>
      <dd>{props.data.subnet}</dd>
    </dl>
  </div>
);

EventIPGeoloc.propTypes = {
  data: PropTypes.any,
};

export default EventIPGeoloc;
