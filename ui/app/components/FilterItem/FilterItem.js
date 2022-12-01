import React from 'react';
import PropTypes from 'prop-types';
import { EditOutlined, CloseOutlined } from '@ant-design/icons';
import { sections } from 'ui/constants';
import styled from 'styled-components';
import { Tooltip } from 'antd';

const HuntFilter = styled.span`
  display: flex !important;
  padding: 0px !important;
  align-items: center;
  background-color: ${p => (p.disabled ? '#c2c2c2' : '#005792')};
  border-radius: 0px;
  box-sizing: border-box;
  color: rgb(255, 255, 255);
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  height: 21.5px;
  line-height: 11px;
  list-style: none outside none;
  margin: 1px;
  text-align: center;
  vertical-align: baseline;
  white-space: normal;

  &.label-not::before {
    content: 'Not';
    background: #9c9c9c;
    display: block;
    float: left;
    padding: 4px 8px;
    margin: 1px 0 1px 1px;
    font-weight: bold;
  }

  & .label-content {
    padding: 4px 8px;
  }
`;

const LabelContent = styled.div`
  box-sizing: border-box;
  color: rgb(255, 255, 255);
  display: block;
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  height: 19px;
  line-height: 11px;
  list-style: none outside none;
  padding: 4px 8px;
  text-align: center;
  text-size-adjust: 100%;
  white-space: normal;
  cursor: default;
`;

const FilterActionButton = styled.a`
  padding: 5px !important;
  margin: 0 !important;
  color: #ffffff;
  cursor: ${p => (p.disabled ? 'not-allowed' : 'pointer')};
  &:hover {
    color: #ffffff;
  }
`;

const EditFilterButton = styled(FilterActionButton)`
  &:hover {
    background: ${p => (p.disabled ? 'none' : '#8a8382')};
  }
`;

const DeleteFilterButton = styled(FilterActionButton)`
  &:hover {
    background: ${p => (p.disabled ? 'none' : '#b70505')};
  }
`;

const FilterItem = props => {
  const negated = props.filter.negated ? 'label-not' : '';
  const displayValue = props.filter.label ? props.filter.label : `${props.filter.id}:${props.filter.value}`;
  return (
    <li>
      <Tooltip title={props.disabled ? 'Filters are not applicable' : null}>
        <HuntFilter className={`${negated}`} disabled={props.disabled}>
          <LabelContent data-test="hunt-filter__filtered">{displayValue}</LabelContent>
          <div style={{ display: 'flex' }}>
            {props.filterType !== sections.HISTORY && (
              <EditFilterButton
                href="#"
                onClick={e => {
                  e.preventDefault();
                  props.onEdit();
                }}
              >
                <EditOutlined />
              </EditFilterButton>
            )}
            {props.children}
            <DeleteFilterButton
              href="#"
              onClick={e => {
                e.preventDefault();
                props.onRemove();
              }}
            >
              <CloseOutlined />
            </DeleteFilterButton>
          </div>
        </HuntFilter>
      </Tooltip>
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
  disabled: PropTypes.bool,
};

export default FilterItem;
