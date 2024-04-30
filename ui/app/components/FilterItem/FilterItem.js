import React, { useEffect, useState } from 'react';

import { EditOutlined, CloseOutlined, StopOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { message, Tooltip } from 'antd';
import PropTypes from 'prop-types';

import FilterButton from 'ui/components/FilterButton';
import FilterEditModal from 'ui/components/FilterEditModal';
import { useStore } from 'ui/mobx/RootStoreProvider';

import * as Style from './style';

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
      <Style.FilterContainer
        className={props.filter.negated ? 'label-not' : ''}
        disabled={props.disabled}
        suspended={props.filter.suspended}
        data-test={`${filterItemDataTest}`}
      >
        <Style.FilterLabels>
          {props.filter.negated && (
            <Tooltip title="Negated filter">
              <Style.SilverLabelNot>Not</Style.SilverLabelNot>
            </Tooltip>
          )}
          {!props.filter?.fullString && (
            <Tooltip title="Wildcard filter">
              <Style.SilverLabelAsterisk>*</Style.SilverLabelAsterisk>
            </Tooltip>
          )}
        </Style.FilterLabels>
        <Style.FilterContent>
          {/* Filter Value */}
          <Style.FilterText>
            {/* Filter Icon */}
            <Style.FilterIconsContainer>
              {props.filter?.icon && (
                <Tooltip title="Host ID Filter">
                  <FilterButton icon={props.filter.icon} />
                </Tooltip>
              )}
            </Style.FilterIconsContainer>
            {/* Filter Label */}
            <Tooltip title={props.disabled ? 'Filters are not applicable' : null}>
              <Style.FilterLabel data-test="hunt-filter__filtered" hasIcon={!!props.filter?.icon}>
                {props.filter.label}
              </Style.FilterLabel>
            </Tooltip>
          </Style.FilterText>
          {/* Filter Buttons */}
          <Style.FilterIconsContainer>
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
          </Style.FilterIconsContainer>
        </Style.FilterContent>
      </Style.FilterContainer>
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
