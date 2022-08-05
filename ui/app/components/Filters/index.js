import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Cascader, Col, Divider, Input, Row, Space, Switch, Select } from 'antd';
import { TagOutlined, CloseOutlined } from '@ant-design/icons';
import UICard from 'ui/components/UIElements/UICard';
import styled from 'styled-components';
import { useInjectSaga } from 'utils/injectSaga';
import { useInjectReducer } from 'utils/injectReducer';
import ruleSetReducer from 'ui/stores/filters/reducer';
import ruleSetSaga from 'ui/stores/filters/saga';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetsSelectors from 'ui/stores/filters/selectors';
import strGlobalSelectors from 'ui/containers/App/selectors';
import strGlobalActions from 'ui/containers/App/actions';
import * as huntGlobalStore from 'ui/containers/HuntApp/stores/global';
import FilterList from 'ui/components/FilterList/index';
import { sections } from 'ui/constants';
import ErrorHandler from 'ui/components/Error';
import FilterSetSave from 'ui/components/FilterSetSaveModal';
import Sort from 'ui/components/Sort';
import { HUNT_FILTER_SETS } from 'ui/config/Api';
import { COLOR_ERROR } from 'ui/constants/colors';
import isIP from 'ui/helpers/isIP';

import { useDispatch, useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import { loadFilterSets } from 'ui/components/FilterSets/store';
import ActionsButtons from '../ActionsButtons';
import request from '../../utils/request';
const { Option } = Select;

const FilterError = styled.span`
  color: ${COLOR_ERROR};
  font-size: 10px;
`;

const FilterContainer = styled.div`
  display: grid;
  grid-gap: 10px;
  grid-template-columns: 1fr repeat(3, 135px);
`;

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
`;

const Filter = ({ page, section, queryTypes, onSortChange, sortValues }) => {
  // Component setup
  useInjectReducer({ key: 'ruleSet', reducer: ruleSetReducer });
  useInjectSaga({ key: 'ruleSet', saga: ruleSetSaga });
  const dispatch = useDispatch();

  // Selectors handlers
  const user = useSelector(strGlobalSelectors.makeSelectUser());
  const filters = useSelector(huntGlobalStore.makeSelectGlobalFilters());
  const historyFilters = useSelector(huntGlobalStore.makeSelectHistoryFilters());
  const alertTag = useSelector(huntGlobalStore.makeSelectAlertTag());
  const filterFields = useSelector(ruleSetsSelectors.makeSelectFilterOptions(queryTypes));
  const supportedActions = useSelector(ruleSetsSelectors.makeSelectSupportedActions());
  const saveFiltersModal = useSelector(ruleSetsSelectors.makeSelectSaveFiltersModal());
  const supportedActionsPermissions = user && user.data && user.data.permissions && user.data.permissions.includes('rules.ruleset_policy_edit');

  // State handlers
  const [valid, setValid] = useState('');
  const [searchString, setSearchString] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);
  const [selectedItems, setSelectedItems] = useState([]);

  // Effects handlers
  useEffect(() => {
    dispatch(ruleSetsActions.ruleSetsRequest());
    if (page !== 'HISTORY') {
      dispatch(ruleSetsActions.huntFilterRequest());
    }
    if (supportedActionsPermissions) {
      dispatch(ruleSetsActions.supportedActionsRequest(filters));
    }
  }, [filters, supportedActionsPermissions]);

  const getTreeOptions = useCallback(
    (data, parentType, level = 0) =>
      data.map(o => ({
        label: `${o.title || o.label}`,
        value: o.id,
        children: parentType !== 'complex-select' ? getTreeOptions(o.filterCategories || o.filterValues || [], o.filterType, level + 1) : [],
      })),
    [filterFields],
  );

  const getFlatOptions = useCallback(
    data => data.reduce((prev, cur) => [...prev, cur, ...getFlatOptions(cur.filterCategories || cur.filterValues || [])], []),
    [filterFields],
  );

  const treeOptions = useMemo(() => getTreeOptions(filterFields), [filterFields]);
  const flatOptions = useMemo(() => getFlatOptions(filterFields), [filterFields]);

  const onChange = useCallback(
    value => {
      const item = flatOptions.filter(d => value.indexOf(d.id) > -1);
      setSelectedItems(item);
      setSelectedIds(value);
      setValid('');
    },
    [filterFields, flatOptions],
  );

  const field = useMemo(() => selectedItems.find(s => flatOptions.find(f => f.id === s.id)), [selectedItems]);

  // Always extracted from first level
  const {
    // id, // <string>
    // title, // <string>
    placeholder, // <string>
    filterType, // <hunt | select | text | complex-select-text | complex-select | complex-select-text | number>
    // filterValues, // undefined || if filterType IS select/complex-select-text/complex-select => FilterValue[{id,label]
    valueType, // undefined || if filterType NOT select/complex-select-text/complex-select => text || positiveint || ip
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
  const filterSubCategory = ((filterCategory && filterCategory.filterValues) || []).find(fv => selectedItems.find(si => fv.id === si.id));

  useEffect(() => {
    if (filterType === 'select' && selectedItems.length > 0) {
      filterAdded(field, selectedItems[1], false);
    }
  }, [selectedItems]);

  const activeFilters = useMemo(() => {
    const stack = section === sections.HISTORY ? historyFilters : filters;
    const result = [];
    stack.forEach(item => {
      if (!item.query || queryTypes.indexOf('all') > -1 || queryTypes.indexOf(item.query) !== -1) {
        result.push(item);
      }
    });
    return result;
  }, [filters, historyFilters, section]);

  const displayRender = (labels, selectedOptions) =>
    labels.map((label, i) => {
      const option = selectedOptions[i];
      if (i === labels.length - 1) {
        return <span key={option.value}>{label}</span>;
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

    dispatch(
      huntGlobalStore.addFilter(section, {
        label: filterText,
        id: fieldId,
        value: fvalue,
        negated: false,
        query: field.queryType,
        fullString,
      }),
    );
    setSelectedItems([]);
    setSelectedIds([]);
    setSearchString('');
  };

  const [errors, setErrors] = useState([]);
  const [filterSetName, setFilterSetName] = useState('');
  const [filterSetShared, setFilterSetShared] = useState(false);
  const [filterSetDescription, setFilterSetDescription] = useState('');

  const submitFilterSets = () => {
    setErrors([]);

    const filtersCopy = [...filters];

    if (process.env.REACT_APP_HAS_TAG === '1') {
      filtersCopy.push(alertTag);
    }

    request(`/${HUNT_FILTER_SETS}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: filterSetName,
        page,
        content: filtersCopy,
        share: filterSetShared,
        description: filterSetDescription,
      }),
    })
      .then(() => {
        // this.props.loadFilterSets();
        dispatch(loadFilterSets());
        dispatch(ruleSetsActions.saveFiltersModal(false));
        setErrors([]);
        setFilterSetName('');
        setFilterSetShared(false);
        setFilterSetDescription('');
      })
      .catch(error => {
        let errors = error.response.data;

        if (error.response.status === 403) {
          const noRights = user.isActive && !user.permissions.includes('rules.events_edit') && filterSetShared;
          if (noRights) {
            errors = { permission: ['Insufficient permissions. "Shared" is not allowed.'] };
          }
        }
        setErrors(errors);
      });
  };

  const validate = (type, value) => {
    if (value.length > 0) {
      if (type === 'ip') {
        setValid(isIP(value) ? '' : 'Enter a valid IP address');
      }
      if (type === 'positiveint') {
        setValid(parseInt(value, 10) >= 0 ? '' : 'Enter a positive integer');
      }
    } else {
      setValid('');
    }
  };

  return (
    <UICard>
      <FilterContainer>
        <div>
          <Title>Filters</Title>
          <div style={{ display: 'flex', flex: 1, gap: 8 }}>
            <div>
              <CascaderStyled value={selectedIds} options={treeOptions} displayRender={displayRender} onChange={value => onChange(value)} />
            </div>
            {field && filterType !== 'complex-select' && filterType !== 'select' && (
              <div style={{ display: 'flex', flex: 1, flexDirection: 'column' }}>
                <Input
                  type={filterType === 'number' ? 'number' : 'text'}
                  value={searchString}
                  onChange={e => {
                    validate(valueType, e.target.value);
                    setSearchString(e.target.value);
                  }}
                  placeholder={placeholder}
                  onPressEnter={event => {
                    const value = filterType === 'number' ? parseInt(event.target.value, 10) : event.target.value;
                    if (valid.length === 0 && ((value && typeof value === 'string' && value.length > 0) || typeof value === 'number')) {
                      filterAdded(field, value, false);
                    }
                  }}
                />
                <FilterError>{valid}</FilterError>
              </div>
            )}
            {filterType === 'complex-select' && (
              <Select
                style={{ width: 200 }}
                showSearch
                placeholder={field && field.placeholder}
                optionFilterProp="children"
                onChange={value => {
                  filterAdded(filterCategory, value, false);
                }}
                filterOption={(input, option) => option.children.toLowerCase().includes(input.toLowerCase())}
              >
                {filterCategory && filterCategory.filterValues.map(v => <Option value={v.id}>{v.label}</Option>)}
              </Select>
            )}
          </div>
          <Divider style={{ margin: '15px 0' }} />
          <Row>
            <Col md={24}>{activeFilters && activeFilters.length > 0 && <FilterList filters={activeFilters} filterType={section} />}</Col>
          </Row>
        </div>
        <div>
          <Title>Additional</Title>
          <Space direction="vertical">
            <Space>
              <Switch
                size="small"
                checkedChildren="ON"
                unCheckedChildren="OFF"
                defaultChecked={alertTag.value.alerts}
                onChange={() => dispatch(huntGlobalStore.setTag('alerts', !alertTag.value.alerts))}
              />{' '}
              Alerts
            </Space>
            <Space>
              <Switch
                size="small"
                checkedChildren="ON"
                unCheckedChildren="OFF"
                defaultChecked={alertTag.value.sightings}
                onChange={() => dispatch(huntGlobalStore.setTag('sightings', !alertTag.value.sightings))}
              />{' '}
              Sightings
            </Space>
            {['SIGNATURES', 'HOSTS_LIST', 'HISTORY'].indexOf(page) > -1 && (
              <Sort page={page} onChange={(option, direction) => onSortChange(option, direction)} value={sortValues} />
            )}
          </Space>
        </div>
        {/* {page !== 'HISTORY' && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && ( */}
        {page !== 'HISTORY' && (
          <div>
            <Title>Tags Filters</Title>
            <Space direction="vertical">
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.informational}
                  onChange={() => dispatch(huntGlobalStore.setTag('informational', !alertTag.value.informational))}
                />{' '}
                Informational
              </Space>
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.relevant}
                  onChange={() => dispatch(huntGlobalStore.setTag('relevant', !alertTag.value.relevant))}
                />{' '}
                Relevant
              </Space>
              <Space>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={alertTag.value.untagged}
                  onChange={() => dispatch(huntGlobalStore.setTag('untagged', !alertTag.value.untagged))}
                />{' '}
                Untagged
              </Space>
            </Space>
          </div>
        )}
        {page !== 'HISTORY' && (
          <div>
            <Title>Actions</Title>
            <ActionsSpace direction="vertical">
              <Space>
                <CloseOutlined style={{ width: 24 }} />
                {filters.length > 0 && (
                  <a href="#" onClick={() => dispatch(huntGlobalStore.clearFilters(section))}>
                    Clear Filters
                  </a>
                )}
                {filters.length === 0 && <>Clear Filters</>}
              </Space>
              <Space>
                <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                  <path d="M0 0h24v24H0V0z" fill="none" />
                  <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z" />
                </svg>
                <a href="#" onClick={() => dispatch(strGlobalActions.setFilterSets(true))}>
                  Load Filter Set
                </a>
              </Space>
              <Space>
                <svg enableBackground="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                  <g>
                    <rect fill="none" height="24" width="24" />
                  </g>
                  <g>
                    <path d="M14,10H3v2h11V10z M14,6H3v2h11V6z M18,14v-4h-2v4h-4v2h4v4h2v-4h4v-2H18z M3,16h7v-2H3V16z" />
                  </g>
                </svg>
                {filters.length > 0 && (
                  <a href="#" onClick={() => dispatch(ruleSetsActions.saveFiltersModal(true))}>
                    Save Filter Set
                  </a>
                )}
                {filters.length === 0 && <>Save Filter Set</>}
              </Space>
              <Space>
                <TagOutlined style={{ width: 24 }} />
                <ErrorHandler>
                  <ActionsButtons supportedActions={supportedActions} />
                </ErrorHandler>
              </Space>
            </ActionsSpace>
          </div>
        )}
      </FilterContainer>
      <FilterSetSave
        title="Create new Filter Set"
        showModal={saveFiltersModal}
        close={() => {
          dispatch(ruleSetsActions.saveFiltersModal(false));
        }}
        errors={errors}
        handleDescriptionChange={event => setFilterSetDescription(event.target.value)}
        handleComboChange={undefined}
        handleFieldChange={event => setFilterSetName(event.target.value)}
        setSharedFilter={event => setFilterSetShared(event.target.checked)}
        submit={() => submitFilterSets()}
        page={page}
        noRights={false}
      />
    </UICard>
  );
};

Filter.propTypes = {
  page: PropTypes.oneOf(['SIGNATURES', 'DASHBOARDS', 'ALERTS', 'HISTORY', 'HOSTS_LIST']),
  section: PropTypes.string.isRequired,
  queryTypes: PropTypes.array.isRequired,
  onSortChange: PropTypes.func.isRequired,
  sortValues: PropTypes.shape({
    option: PropTypes.string,
    direction: PropTypes.string,
  }),
};

export default Filter;
