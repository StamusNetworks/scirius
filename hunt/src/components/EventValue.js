import React from 'react';
import PropTypes from 'prop-types';
import { Icon } from 'patternfly-react';
import EventValueInfo from 'hunt_common/components/EventValueInfo';
import ErrorHandler from './Error';

const EventValue = (props) => <div className="value-field-complete">
    <span className="value-field" title={props.value}>{props.value}</span>
    <span className={'value-actions'}>
        <ErrorHandler>
            <EventValueInfo field={props.field} value={props.value} />
            {props.magnifiers && <a onClick={() => { props.addFilter(props.field, props.value, false); }}> <Icon type="fa" name="search-plus" /></a>}
            {props.magnifiers && <a onClick={() => { props.addFilter(props.field, props.value, true); }}> <Icon type="fa" name="search-minus" /></a>}
        </ErrorHandler>
    </span>
    {props.right_info && <span className="value-right-info">{props.right_info}</span>}
</div>

EventValue.defaultProps = {
    magnifiers: true,
}

EventValue.propTypes = {
    addFilter: PropTypes.any,
    right_info: PropTypes.any,
    field: PropTypes.any,
    value: PropTypes.any,
    magnifiers: PropTypes.bool,
};

export default EventValue;
