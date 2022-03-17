import React from 'react';
import PropTypes from 'prop-types';
import { Tooltip } from 'antd';
import { InfoCircleOutlined } from '@ant-design/icons';
import EventIPInfo from 'components/EventIPInfo';

const EventValueInfo = (props) => {
  if (!props.magnifiers) {
    return null;
  }

  if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(props.field) > -1) {
    if (process.env.REACT_APP_ONYPHE_API_KEY) {
      return <EventIPInfo key="event_ip_info" value={props.value} />;
    }
    return (
      <Tooltip title="external info" id="tooltip-top" key="virustotal_link" trigger="hover" style={{ cursor: 'default' }}>
        <a href={`https://www.virustotal.com/gui/ip-address/${props.value}`} target="_blank">
          {' '}
          <InfoCircleOutlined />
        </a>
      </Tooltip>
    );
  }
  if (['src_port', 'dest_port', 'host_id.services.port'].indexOf(props.field) > -1) {
    return (
      <Tooltip title="external info" id="tooltip-top" key="dshield_link" trigger="hover" style={{ cursor: 'default' }}>
        <a href={`https://www.dshield.org/port.html?port=${props.value}`} target="_blank">
          {' '}
          <InfoCircleOutlined />
        </a>
      </Tooltip>
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
