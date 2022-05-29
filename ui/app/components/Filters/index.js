import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Cascader, Col, Divider, Input, Row, Space, Switch } from 'antd';
import UICard from 'ui/components/UIElements/UICard';
import styled from 'styled-components';
import { useInjectSaga } from 'utils/injectSaga';
import { useInjectReducer } from 'utils/injectReducer';
import ruleSetReducer from 'ui/stores/filters/reducer';
import ruleSetSaga from 'ui/stores/filters/saga';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetsSelectors from 'ui/stores/filters/selectors';
import strGlobalSelectors from 'ui/containers/App/selectors';
import * as huntGlobalStore from 'ui/containers/HuntApp/stores/global';
import FilterList from 'ui/components/FilterList/index';
import FilterSets from 'ui/components/FilterSets';
import { sections } from 'ui/constants';

import { useDispatch, useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import ActionsButtons from '../ActionsButtons';

const Title = styled.div`
  padding: 0px 0px 5px 0px;
  color: #005792;
  font-weight: bold;
`;

const ActionsSpace = styled(Space)`
  .ant-space-item {
    height: 14px;
  }
`;

const CascaderStyled = styled(Cascader)`

  width: max-content;
  position: relative;
  line-height: 2.2715;
  min-width: 150px;

  .ant-cascader-picker-label {
    width: max-content;
    position: relative;
    padding-right: 30px;

    top: initial;
    left: initial;
    height: initial;
    margin-top: initial;
    overflow: initial;
    line-height: initial;
    white-space: initial;
    text-overflow: initial;
}

.ant-cascader-input {
  width: 100%;
  position: absolute;
  left: 0;
}
`

const Filter = ({ page, section, queryTypes }) => {
  // Component setup
  useInjectReducer({ key: 'ruleSet', reducer: ruleSetReducer });
  useInjectSaga({ key: 'ruleSet', saga: ruleSetSaga });
  const dispatch = useDispatch();

  // Selectors handlers
  const user = useSelector(strGlobalSelectors.makeSelectUser());
  const filters = useSelector(huntGlobalStore.makeSelectGlobalFilters());
  const historyFilters = useSelector(huntGlobalStore.makeSelectHistoryFilters());
  const alertTag = useSelector(huntGlobalStore.makeSelectAlertTag());
  const filterFields = useSelector(ruleSetsSelectors.makeSelectFilterOptions(section));
  const supportedActions = useSelector(ruleSetsSelectors.makeSelectSupportedActions());
  const supportedActionsPermissions = user && user.data && user.data.permissions && user.data.permissions.includes('rules.ruleset_policy_edit');

  // State handlers
  const [ selectedItems, setSelectedItems ] = useState([]);
  const [ filterSets, setFilterSets ] = useState(false);

  // Effects handlers
  useEffect(() => {
    dispatch(ruleSetsActions.ruleSetsRequest());
    dispatch(ruleSetsActions.huntFilterRequest());
    if (supportedActionsPermissions) {
      dispatch(ruleSetsActions.supportedActionsRequest(filters));
    }
  }, []);

  const getTreeOptions = useCallback((data) => data.map(o => ({
      label: `${o.title || o.label}`,
      value: o.id,
      children: getTreeOptions(o.filterCategories || o.filterValues || [])
    })), [filterFields]);

  const getFlatOptions = useCallback((data) => data.reduce((prev, cur) => [
        ...prev,
        cur,
        ...getFlatOptions(cur.filterCategories || cur.filterValues || [])
      ], []), [filterFields]);

  const treeOptions = useMemo(() => getTreeOptions(filterFields), [filterFields]);
  const flatOptions = useMemo(() => getFlatOptions(filterFields), [filterFields]);

  const onChange = useCallback((value) => {
    const item = flatOptions.filter(d => value.indexOf(d.id) > -1);
    setSelectedItems(item);
  }, [filterFields, flatOptions]);

  const field = useMemo(() => selectedItems.find(s => flatOptions.find(f => f.id === s.id)), [selectedItems]);

  // Always extracted from first level
  const {
    // id, // <string>
    // title, // <string>
    placeholder, // <string>
    filterType, // <hunt | select | text | complex-select-text | complex-select | complex-select-text | number>
    // filterValues, // undefined || if filterType IS select/complex-select-text/complex-select => FilterValue[{id,label]
    // valueType, // undefined || if filterType NOT select/complex-select-text/complex-select => text || positiveint || ip
    // queryType, // undefined || filter_host_id || rest || filter ||
    filterCategories, // undefined || if filterType IS complex-select-text =>
    /*
      id	title	filterType	valueType	placeholder
      id	title	filterType	valueType	placeholder	filterValues
      id	title	filterValues
      id	title	filterValues
     */
    // sub_placeholder,
    // filterCategoriesPlaceholder
  } = field || {};

  // Second level category
  const filterCategory = (filterCategories || []).find(fc => selectedItems.find(si => fc.id === si.id));
  const filterSubCategory = (filterCategory && filterCategory.filterValues || []).find(fv => selectedItems.find(si => fv.id === si.id));

  useEffect(() => {
    if (filterType === 'select' && selectedItems.length > 0) {
      filterAdded(field, selectedItems[1], false);
    }
  }, [selectedItems]);

  const activeFilters = useMemo(() => {
    const stack = section === sections.HISTORY ? historyFilters : filters;
    const result = [];
    stack.forEach((item) => {
      if (!item.query || queryTypes.indexOf(item.query) !== -1) {
        result.push(item);
      }
    });
    return result;
  }, [filters, historyFilters, section]);

  const displayRender = (labels, selectedOptions) =>
    labels.map((label, i) => {
      const option = selectedOptions[i];
      if (i === labels.length - 1) {
        return (<span key={option.value}>{label}</span>);
      }
      return <span key={option.value}>{label} / </span>;
    });

  const filterAdded = (field, value, fullString) => {
    let filterText = '';
    let fieldId = field.id;
    if (['msg', 'not_in_msg', 'content', 'not_in_content'].indexOf(field.id) !== -1) {
      // eslint-disable-next-line no-param-reassign
      value = value.trim();
    }
    if (field.filterType !== 'complex-select-text') {
      if (field.filterType === 'select' || field.filterType === 'complex-select') {
        filterText = field.title;
        fieldId = field.id;
      } else if (field.title && field.queryType !== 'filter_host_id') {
        filterText = field.title;
      } else {
        filterText = field.id;
      }
    } else {
      if (filterCategory) {
        filterText = `${filterCategory.id}.${filterSubCategory.id}`;
      } else {
        filterText = `${filterCategory.id}`;
      }
      fieldId = filterText;
    }
    filterText += ': ';

    if (value.filterCategory) {
      filterText += `${value.filterCategory.title || value.filterCategory}-${value.filterValue.title || value.filterValue}`;
    } else if (value.title) {
      filterText += value.title;
    } else if (value.label) {
      filterText += value.label;
    } else {
      filterText += value;
    }

    let fvalue;
    if (typeof value === 'object') {
      if (field.id !== 'alert.tag') {
        fvalue = value.id;
      } else {
        fvalue = value;
      }
    } else {
      fvalue = value;
    }

    dispatch(huntGlobalStore.addFilter(section, {
      label: filterText,
      id: fieldId,
      value: fvalue,
      negated: false,
      query: field.queryType,
      fullString,
    }));
  };

  return (
    <UICard>
      {filterSets && (<FilterSets close={() => setFilterSets(false)} />)}
      <Row gutter={[15,15]}>
        <Col md={18}>
          <Title>Filters</Title>
          <div style={{ display: 'flex', flex: 1, gap: 8 }}>
            <div style={{ display: 'flex' }}>
              <CascaderStyled
                options={treeOptions}
                displayRender={displayRender}
                onChange={(value) => onChange(value)}
              />
            </div>
            {filterType !== 'complex-select' && filterType !== 'select' && (
              <div style={{ display: 'flex', flex: 1 }}>
                <Input
                  placeholder={placeholder}
                  onPressEnter={(event) => {
                    const { value } = event.target;
                    if (value && value.length > 0) {
                      filterAdded(field, value, false);
                    }
                  }}
                />
              </div>
            )}
          </div>
          <Divider style={{ margin: '18px 0'}} />

          <Row>
            <Col md={12}>

              {activeFilters && activeFilters.length > 0 && (
                <div>
                  <FilterList filters={activeFilters} filterType={section} />
                </div>
              )}


            </Col>
            <Col md={12}>

            </Col>
          </Row>
        </Col>
        {page !== 'HISTORY' && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && (
          <Col md={3}>
            <Title>Tags Filters</Title>
            <Space direction='vertical'>
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.informational}
                  onChange={() => dispatch(huntGlobalStore.setTag('informational', !alertTag.value.informational))}
                /> Informational
              </Space>
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.relevant}
                  onChange={() => dispatch(huntGlobalStore.setTag('relevant', !alertTag.value.relevant))}
                /> Relevant
              </Space>
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.untagged}
                  onChange={() => dispatch(huntGlobalStore.setTag('untagged', !alertTag.value.untagged))}
                /> Untagged
              </Space>
            </Space>
          </Col>
        )}
        <Col md={3}>
          <Title>Actions</Title>
          <ActionsSpace direction='vertical'>
            <Space>
              <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                <path d="M0 0h24v24H0V0z" fill="none" />
                <path d="M5 13h14v-2H5v2zm-2 4h14v-2H3v2zM7 7v2h14V7H7z" />
              </svg>
              <a href='#' onClick={() => dispatch(huntGlobalStore.clearFilters(section)) }>
                Clear Filters
              </a>
            </Space>
            <Space>
              <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                <path d="M0 0h24v24H0V0z" fill="none" />
                <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z" />
              </svg>
              <a href='#' onClick={() => setFilterSets(true)}>Load Filter Set</a>
            </Space>
            {page !== 'HISTORY' && (
              <Space>
                <svg enableBackground="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                  <g>
                    <rect fill="none" height="24" width="24" />
                  </g>
                  <g>
                    <path d="M14,10H3v2h11V10z M14,6H3v2h11V6z M18,14v-4h-2v4h-4v2h4v4h2v-4h4v-2H18z M3,16h7v-2H3V16z" />
                  </g>
                </svg>
                Save Filter Set
              </Space>
            )}
            <Space>
              <svg enableBackground="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                <g>
                  <rect fill="none" height="24" width="24" />
                </g>
                <g>
                  <path d="M14,10H3v2h11V10z M14,6H3v2h11V6z M18,14v-4h-2v4h-4v2h4v4h2v-4h4v-2H18z M3,16h7v-2H3V16z" />
                </g>
              </svg>
              <ActionsButtons supportedActions={supportedActions} />
            </Space>
          </ActionsSpace>
        </Col>
      </Row>
    </UICard>
  )
}

Filter.propTypes = {
  page: PropTypes.oneOf(['SIGNATURES', 'DASHBOARD', 'ALERTS', 'HISTORY']),
  section: PropTypes.string.isRequired,
  queryTypes: PropTypes.array.isRequired,
}

export default Filter;
