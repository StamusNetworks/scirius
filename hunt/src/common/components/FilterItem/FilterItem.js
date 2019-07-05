import React from 'react';
import PropTypes from 'prop-types';
import './style.css';

const FilterItem = (props) => {
    const negated = (props.negated) ? 'label-not' : '';

    return <li>
        <span className={`hunt-filter label label-info ${negated}`}>
            <div className={'label-content'}>{props.id}:{props.value}</div>
            <a
                href="#"
                className="pf-edit-button filter-action edit"
                onClick={(e) => {
                    e.preventDefault();
                    props.onEdit()
                }}
            >
                <span className="pficon pficon-edit" aria-hidden="true" />
                <span className="sr-only">Edit</span>
            </a>
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

FilterItem.propTypes = {
    value: PropTypes.oneOfType([
        PropTypes.string,
        PropTypes.number
    ]).isRequired,
    id: PropTypes.string.isRequired,
    negated: PropTypes.bool.isRequired,
    onRemove: PropTypes.func.isRequired,
    onEdit: PropTypes.func.isRequired,
    children: PropTypes.any,
}

export default FilterItem;
