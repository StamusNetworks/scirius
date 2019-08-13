import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Icon } from 'patternfly-react';
import EventValueInfo from 'hunt_common/components/EventValueInfo';
import ErrorHandler from './Error';
import { addFilter, sections } from '../containers/App/stores/global';

const EventValue = (props) => <div className="value-field-complete">
    <span className="value-field" title={`${props.value}\n"Ctrl + left click" to copy`}>{props.value}</span>
    <span className={'value-actions'}>
        <ErrorHandler>
            <EventValueInfo field={props.field} value={props.value} magnifiers={props.magnifiers} />
            {props.magnifiers && <a onClick={() => props.addFilter(sections.GLOBAL, { id: props.field, value: props.value, label: `${props.field}: ${props.value}`, fullString: true, negated: false })}> <Icon type="fa" name="search-plus" /></a>}
            {props.magnifiers && <a onClick={() => props.addFilter(sections.GLOBAL, { id: props.field, value: props.value, label: `${props.field}: ${props.value}`, fullString: true, negated: true })}> <Icon type="fa" name="search-minus" /></a>}
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

const mapDispatchToProps = (dispatch) => ({
    addFilter: (section, filter) => dispatch(addFilter(section, filter))
});

export default connect(null, mapDispatchToProps)(EventValue);
