import React from 'react';
import PropTypes from 'prop-types';
import { sections } from 'hunt_common/constants';
import './style.css';

const FilterItem = (props) => {
    const negated = (props.filter.negated) ? 'label-not' : '';
    const displayValue = (props.filter.label) ? props.filter.label : `${props.filter.id}:${props.filter.value}`;
    return <li>
        <span className={`hunt-filter label label-info ${negated}`}>
            <div className={'label-content'}>{displayValue}</div>
            {props.filterType !== sections.HISTORY && <a
                href="#"
                className="pf-edit-button filter-action edit"
                onClick={(e) => {
                    e.preventDefault();
                    props.onEdit()
                }}
            >
                <span className="pficon pficon-edit" aria-hidden="true" />
                <span className="sr-only">Edit</span>
            </a>}
            { props.children }
            <a
                href="#"
                className="pf-remove-button filter-action delete"
                onClick={(e) => {
                    e.preventDefault();
                    props.onRemove();
                }}
            >
                <span className="pficon pficon-close" aria-hidden="true" />
                <span className="sr-only">Remove</span>
            </a>
        </span>
    </li>
}

FilterItem.defaultProps = {
    filterType: sections.GLOBAL,
}

FilterItem.propTypes = {
    onEdit: PropTypes.func.isRequired,
    onRemove: PropTypes.func.isRequired,
    children: PropTypes.any,
    filterType: PropTypes.string,
    filter: PropTypes.object.isRequired
}

export default FilterItem;
