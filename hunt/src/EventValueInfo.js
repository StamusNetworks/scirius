import React from 'react';
import PropTypes from 'prop-types';
import { Icon } from 'patternfly-react';
import EventIPInfo from './EventIPInfo';

const EventValueInfo = (props) => {
    if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(props.field) > -1) {
        if (process.env.REACT_APP_ONYPHE_API_KEY) {
            return (<EventIPInfo value={props.value} />);
        }
        return (
            <a href={`https://www.onyphe.io/search/?query=${props.value}`} target="_blank"> <Icon type="fa" name="info-circle" /></a>
        );
    }
    return null;
};

EventValueInfo.propTypes = {
    value: PropTypes.any,
    field: PropTypes.any,
};

export default EventValueInfo;
