import React, { useEffect, useState } from 'react';

import { EditOutlined, CloseOutlined, StopOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { message, Tooltip } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import FilterButton from 'ui/components/FilterButton';
import FilterEditModal from 'ui/components/FilterEditModal';
import { useStore } from 'ui/mobx/RootStoreProvider';

const FilterContainer = styled.li`
  display: flex !important;
  padding: 0 !important;
  gap: 10px;
  justify-content: space-between;
  align-items: center;
  text-decoration: ${p => (p.suspended ? 'line-through' : '')};
  background-color: ${p => (p.disabled ? '#c2c2c2' : '#005792')};
  border-radius: 0;
  box-sizing: border-box;
  color: #ffffff;
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  height: 22px;
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
`;

const FilterLabel = styled.span`
  box-sizing: border-box;
  font-family: 'Open Sans', Helvetica, Arial, sans-serif;
  font-size: 11px;
  list-style: none outside none;
  cursor: default;
  padding-left: ${p => (!p?.hasIcon ? '5px' : '0')};
`;

const FilterText = styled.div`
  display: flex;
  align-items: center;
`;

const FilterControls = styled.div`
  display: flex;
`;

const FilterItem = props => {
  const { commonStore } = useStore();
  const filterItemDataTest = props.filter.negated ? 'filter-item-not' : 'filter-item';
  const [messageApi, contextHolder] = message.useMessage();

  const [editForm, setEditForm] = useState(false);

  useEffect(() => {
    if (editForm === true) {
      setTimeout(() => {
        document.querySelector('#input-value-filter').select();
      }, 100);
    }
  }, [editForm]);

  return (
    <React.Fragment>
      {contextHolder}
      <FilterContainer
        className={props.filter.negated ? 'label-not' : ''}
        disabled={props.disabled}
        suspended={props.filter.suspended}
        data-test={`${filterItemDataTest}`}
      >
        {/* Filter Value */}
        <FilterText>
          {/* Filter Icon */}
          {props.filter?.icon && (
            <Tooltip title="Host ID Filter">
              <FilterButton icon={props.filter.icon} />
            </Tooltip>
          )}
          {/* Filter Label */}
          <Tooltip title={props.disabled ? 'Filters are not applicable' : null}>
            <FilterLabel data-test="hunt-filter__filtered" hasIcon={!!props.filter?.icon}>
              {props.filter.label}
            </FilterLabel>
          </Tooltip>
        </FilterText>
        {/* Filter Buttons */}
        <FilterControls>
          {props.filter.category !== 'HISTORY' && (
            <FilterButton
              color="#8a8382"
              icon={<EditOutlined />}
              data-test="filter-edit-button"
              onClick={e => {
                e.preventDefault();
                setEditForm(true);
              }}
            />
          )}
          {props.children}
          {props.filter.category !== 'HISTORY' && (
            <Tooltip title={props.filter.suspended ? 'Enable filter' : 'Suspend filter'}>
              <FilterButton
                color="#8a8382"
                icon={props.filter.suspended ? <CheckCircleOutlined /> : <StopOutlined />}
                onClick={e => {
                  e.preventDefault();
                  props.filter.suspended = !props.filter.suspended;
                  messageApi.open({
                    type: 'success',
                    content: `Filter is ${props.filter.suspended ? 'disabled' : 'enabled'}`,
                  });
                }}
              />
            </Tooltip>
          )}
          <FilterButton
            color="#b70505"
            icon={<CloseOutlined />}
            onClick={e => {
              e.preventDefault();
              if (props.filter.category === 'HISTORY') {
                commonStore.removeHistoryFilter(props.filter.uuid);
              } else {
                commonStore.removeFilter(props.filter.uuid);
              }
            }}
          />
        </FilterControls>
      </FilterContainer>
      {editForm && <FilterEditModal filter={props.filter} onClose={() => setEditForm(false)} />}
    </React.Fragment>
  );
};

FilterItem.propTypes = {
  children: PropTypes.any,
  filter: PropTypes.object.isRequired,
  disabled: PropTypes.bool,
};

export default FilterItem;
