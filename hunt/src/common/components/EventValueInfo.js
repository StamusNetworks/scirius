import React from 'react';
import PropTypes from 'prop-types';
import { Icon } from 'patternfly-react';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import EventIPInfo from '../../components/EventIPInfo';

const EventValueInfo = (props) => {
  if (!props.magnifiers) {
    return null;
  }

  if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(props.field) > -1) {
    if (process.env.REACT_APP_ONYPHE_API_KEY) {
      return <EventIPInfo key="event_ip_info" value={props.value} />;
    }
    return (
      <OverlayTrigger key="onyphe_link" trigger={['hover', 'hover']} placement="top" overlay={<Tooltip id="tooltip-top">external info</Tooltip>}>
        <a href={`https://www.onyphe.io/search/?query=${props.value}`} target="_blank">
          {' '}
          <Icon type="fa" name="info-circle" />
        </a>
      </OverlayTrigger>
    );
  }
  if (['src_port', 'dest_port', 'host_id.services.port'].indexOf(props.field) > -1) {
    return (
      <OverlayTrigger key="dshield_link" trigger={['hover', 'hover']} placement="top" overlay={<Tooltip id="tooltip-top">external info</Tooltip>}>
        <a href={`https://www.dshield.org/port.html?port=${props.value}`} target="_blank">
          {' '}
          <Icon type="fa" name="info-circle" />
        </a>
      </OverlayTrigger>
    );
  }
  return null;
};

EventValueInfo.propTypes = {
  value: PropTypes.any,
  field: PropTypes.any,
  magnifiers: PropTypes.any,
};

export default EventValueInfo;
