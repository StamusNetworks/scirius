import React from 'react';
import PropTypes from 'prop-types';
import { EditOutlined, CloseOutlined } from '@ant-design/icons';
import { sections } from 'ui/constants';
import './style.css';

const FilterItem = (props) => {
  const negated = props.filter.negated ? 'label-not' : '';
  const displayValue = props.filter.label ? props.filter.label : `${props.filter.id}:${props.filter.value}`;
  return (
    <li>
      <span className={`hunt-filter ${negated}`}>
        <div className="label-content" data-test="hunt-filter__filtered">
          {displayValue}
        </div>
        <div className='label-actions'>
          {props.filterType !== sections.HISTORY && (
            <a
              href="#"
              className="filter-action edit"
              onClick={(e) => {
                e.preventDefault();
                props.onEdit();
              }}
            >
              <EditOutlined />
            </a>
          )}
          {props.children}
          <a
            href="#"
            className="filter-action delete"
            onClick={(e) => {
              e.preventDefault();
              props.onRemove();
            }}
          >
            <CloseOutlined />
          </a>
        </div>
      </span>
    </li>
  );
};

FilterItem.defaultProps = {
  filterType: sections.GLOBAL,
};

FilterItem.propTypes = {
  onEdit: PropTypes.func.isRequired,
  onRemove: PropTypes.func.isRequired,
  children: PropTypes.any,
  filterType: PropTypes.string,
  filter: PropTypes.object.isRequired,
};

export default FilterItem;
