import React from 'react';
import PropTypes from 'prop-types';
import { Icon } from 'patternfly-react';
import EventIPInfo from '../../components/EventIPInfo';

const EventValueInfo = (props) => {
    if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(props.field) > -1) {
        if (process.env.REACT_APP_ONYPHE_API_KEY) {
            return <EventIPInfo key="event_ip_info" value={props.value} />;
        }
        return <a key="onyphe_link" href={`https://www.onyphe.io/search/?query=${props.value}`} target="_blank"> <Icon type="fa" name="info-circle" /></a>;
    }
    if (['src_port', 'dest_port', 'host_id.services.port'].indexOf(props.field) > -1) {
        return <a key="dshield_link" href={`https://www.dshield.org/port.html?port=${props.value}`} target="_blank"> <Icon type="fa" name="info-circle" /></a>;
    }
    return null;
};

EventValueInfo.propTypes = {
    value: PropTypes.any,
    field: PropTypes.any,
};

export default EventValueInfo;
