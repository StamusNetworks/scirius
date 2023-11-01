import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { EditOutlined, CloseOutlined, StopOutlined, CheckCircleOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import { Button, Checkbox, Col, Form, Input, InputNumber, message, Modal, Row, Tooltip } from 'antd';
import IP_FIELDS from 'ui/config/ipFields';
import { useStore } from 'ui/mobx/RootStoreProvider';
import { INTERGER_FIELDS_ENDS_WITH, INTERGER_FIELDS_EXACT } from 'ui/maps/FiltersFieldTypes';
import isNumeric from 'ui/helpers/isNumeric';
import Filter from 'ui/utils/Filter';
import FilterButton from 'ui/components/FilterButton';

const ModalHuntFilter = styled(Modal)`
  & .modal-body {
    padding-bottom: 0;
  }
  & .modal-footer {
    margin-top: 0;
  }
`;

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

  const [filterCopy, setFilterCopy] = useState(props.filter.instance);
  const [editForm, setEditForm] = useState(false);

  const isInteger =
    INTERGER_FIELDS_ENDS_WITH.findIndex(item => props.filter.id.endsWith(item)) !== -1 || INTERGER_FIELDS_EXACT.includes(props.filter.id);
  let enableWildcard = !['msg', 'not_in_msg', 'content', 'not_in_content', 'hits_min', 'hits_max', 'es_filter'].includes(props.filter.id);
  enableWildcard = enableWildcard && !IP_FIELDS.includes(props.filter.id) && !isInteger;
  const valid = !filterCopy.fullString && enableWildcard && filterCopy.value.match(/[\s]+/g) ? 'error' : 'success';

  useEffect(() => {
    if (editForm === true) {
      setTimeout(() => {
        document.querySelector('#input-value-filter').select();
      }, 100);
    }
  }, [editForm]);
  const onSave = () => {
    const newFilterValue = isNumeric(filterCopy.value) ? parseInt(filterCopy.value, 10) : filterCopy.value;
    commonStore.replaceFilter(
      props.filter,
      new Filter(filterCopy.id, newFilterValue, {
        negated: filterCopy.negated,
        fullString: filterCopy.fullString,
        suspended: filterCopy.suspended,
      }),
    );
    setEditForm(false);
  };

  const keyListener = ({ keyCode }) => {
    // Enter key handler
    if (keyCode === 13 && valid) {
      onSave();
    }
  };

  const controlType = !isInteger ? 'text' : 'number';

  let helperText = '';
  if (['msg', 'not_in_msg', 'content', 'not_in_content'].includes(props.filter.id)) {
    helperText = 'Case insensitive substring match.';
  } else if (['hits_min', 'hits_max'].includes(props.filter.id)) {
    helperText = '';
  } else if (['es_filter'].includes(props.filter.id)) {
    helperText = 'Free ES filter with Lucene syntax';
  } else if (!filterCopy.fullString && enableWildcard) {
    helperText = (
      <React.Fragment>
        Wildcard characters (<i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>*</i> and{' '}
        <i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>?</i>) can match on word boundaries.
        <br />
        No spaces allowed.
      </React.Fragment>
    );
  } else {
    helperText = 'Exact match';
  }

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
            <Tooltip title="Suspend filter">
              <FilterButton
                color="#8a8382"
                icon={props.filter.suspended ? <CheckCircleOutlined /> : <StopOutlined />}
                onClick={e => {
                  e.preventDefault();
                  commonStore.replaceFilter(props.filter, props.filter.suspend());
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
                commonStore.removeHistoryFilter(props.filter);
              } else {
                commonStore.removeFilter(props.filter);
              }
            }}
          />
        </FilterControls>
      </FilterContainer>
      {editForm && (
        <ModalHuntFilter
          title="Edit filter"
          visible={editForm}
          onCancel={() => setEditForm(false)}
          className="modal-hunt-filter"
          footer={
            <React.Fragment>
              <Button data-test="cancel-edit-filter-button" onClick={() => setEditForm(false)}>
                Cancel
              </Button>
              <Button data-test="save-edit-filter-button" type="primary" disabled={valid === 'error'} onClick={onSave}>
                Save
              </Button>
            </React.Fragment>
          }
        >
          <Form>
            <Form.Item name="name">
              <Row>
                <Col span={4}>
                  <label>Filter</label>
                </Col>
                <Col span={20}>
                  <Form.Item validateStatus={valid}>
                    <span>{props.filter.id}</span>
                    {controlType === 'text' ? (
                      <Input
                        data-test="edit-filter-input-field"
                        id="input-value-filter"
                        value={filterCopy.value}
                        onKeyDown={keyListener}
                        onChange={e => {
                          setFilterCopy({ ...filterCopy, value: filterCopy.id === 'host_id.roles.name' ? e.target.value : e.target.value.trim() });
                        }}
                        style={{ width: '100%' }}
                      />
                    ) : (
                      <InputNumber
                        id="input-value-filter"
                        value={filterCopy.value}
                        onKeyDown={keyListener}
                        onChange={value => setFilterCopy({ ...filterCopy, value })}
                        style={{ width: '100%' }}
                      />
                    )}
                  </Form.Item>
                  <span style={{ color: '#b4b3b5' }}>{helperText}</span>
                </Col>
              </Row>
            </Form.Item>
            <Form.Item name="checkbox-wildcard_view">
              <Row>
                <Col span={6}>
                  <label>Wildcard view</label>
                </Col>
                <Col span={18}>
                  <Checkbox
                    data-test="wildcard-checkbox"
                    onChange={({ target: { checked } }) => setFilterCopy({ ...filterCopy, fullString: !checked })}
                    onKeyDown={keyListener}
                    checked={!filterCopy.fullString && enableWildcard}
                    disabled={!enableWildcard}
                  />
                </Col>
              </Row>
            </Form.Item>

            {!['msg', 'not_in_msg', 'content', 'not_in_content', 'hits_min', 'hits_max'].includes(props.filter.id) && (
              <Form.Item name="checkbox-negated">
                <Row>
                  <Col span={6}>
                    <label>Negated</label>
                  </Col>
                  <Col span={18}>
                    <Checkbox
                      data-test="negated-filter-checkbox"
                      onChange={({ target: { checked } }) => setFilterCopy({ ...filterCopy, negated: checked })}
                      onKeyDown={keyListener}
                      checked={filterCopy.negated}
                    />
                  </Col>
                </Row>
              </Form.Item>
            )}
          </Form>
        </ModalHuntFilter>
      )}
    </React.Fragment>
  );
};

FilterItem.propTypes = {
  children: PropTypes.any,
  filter: PropTypes.object.isRequired,
  disabled: PropTypes.bool,
};

export default FilterItem;
