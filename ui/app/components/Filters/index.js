import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Cascader, Col, Divider, Input, Row, Space, Switch, Select, Affix, Tooltip } from 'antd';
import { PushpinOutlined, PushpinFilled } from '@ant-design/icons';
import { observer } from 'mobx-react-lite';
import UICard from 'ui/components/UIElements/UICard';
import styled from 'styled-components';
import { useInjectSaga } from 'utils/injectSaga';
import { useInjectReducer } from 'utils/injectReducer';
import { useHotkeys } from 'react-hotkeys-hook';
import ruleSetReducer from 'ui/stores/filters/reducer';
import ruleSetSaga from 'ui/stores/filters/saga';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetsSelectors from 'ui/stores/filters/selectors';
import * as huntGlobalStore from 'ui/containers/HuntApp/stores/global';
import FilterList from 'ui/components/FilterList/index';
import { sections } from 'ui/constants';
import FilterSetSaveModal from 'ui/components/FilterSetSaveModal';
import UISwitch from 'ui/components/UIElements/UISwitch';
import UISwitchLabel from 'ui/components/UIElements/UISwitchLabel';
import AdditionalFilters from 'ui/components/AdditionalFilters';
import { COLOR_ERROR } from 'ui/constants/colors';
import { useStore } from 'ui/mobx/RootStoreProvider';
import isIP from 'ui/helpers/isIP';
import Sort from 'ui/components/Sort';

import { useDispatch, useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import Title from './Title.styled';
import Actions from './components/Actions';
const { Option } = Select;

const FilterError = styled.span`
  color: ${COLOR_ERROR};
  font-size: 10px;
`;

const FilterContainer = styled.div`
  display: grid;
  grid-gap: 10px;
  grid-template-columns: 1fr repeat(2, 150px) 10px 150px;
`;

const Separator = styled.div`
  background: #f0f2f5;
  width: 4px;
  margin: -10px 0px -10px -5px;
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

const FiltersSelector = styled.div`
  .ant-cascader-menu {
    height: fit-content;
    max-height: 500px;
    width: 150px;
  }
`;

const Static = styled.div``;

const Filter = ({ page, section, queryTypes, filterTypes, onSortChange, sortValues }) => {
  // Component setup
  useInjectReducer({ key: 'ruleSet', reducer: ruleSetReducer });
  useInjectSaga({ key: 'ruleSet', saga: ruleSetSaga });
  const dispatch = useDispatch();
  const { commonStore } = useStore();

  // Selectors handlers
  const { user, filters } = commonStore;
  const historyFilters = useSelector(huntGlobalStore.makeSelectHistoryFilters());
  const saveFiltersModal = useSelector(ruleSetsSelectors.makeSelectSaveFiltersModal());
  const supportedActionsPermissions = user && user.permissions && user.permissions.includes('rules.ruleset_policy_edit');
  const filtersAreSticky = useSelector(({ ruleSet }) => ruleSet?.filtersAreSticky);
  let filterFields = useSelector(ruleSetsSelectors.makeSelectFilterOptions(filterTypes));

  // we dont want all filters in inventory
  if (page === 'INVENTORY') filterFields = filterFields.filter(obj => obj.title.includes('Hosts:') || obj.title.includes('Network Def'));

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
  }, []);
  useEffect(() => {
    if (supportedActionsPermissions) {
      dispatch(ruleSetsActions.supportedActionsRequest(filters));
    }
  }, [JSON.stringify(filters), supportedActionsPermissions]);

  useHotkeys(
    'shift+i',
    () => {
      commonStore.toggleAlertTag('informational');
    },
    [commonStore.alert.value.informational],
  );
  useHotkeys(
    'shift+r',
    () => {
      commonStore.toggleAlertTag('relevant');
    },
    [commonStore.alert.value.relevant],
  );
  useHotkeys(
    'shift+u',
    () => {
      commonStore.toggleAlertTag('untagged');
    },
    [commonStore.alert.value.untagged],
  );

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
    if ((filterType === 'select' || (filterType === 'complex-select' && !filterCategories)) && selectedItems.length > 0) {
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
        filterText = `${filterCategory.id}`;
        if (filterSubCategory && filterSubCategory.id) {
          filterText += `.${filterSubCategory.id}`;
        }
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
    commonStore.addFilter({
      label: filterText,
      id: fieldId,
      value: fvalue,
      negated: false,
      query: field.queryType,
      fullString,
    });
    setSelectedItems([]);
    setSelectedIds([]);
    setSearchString('');
  };

  const getFiltersCopy = () => {
    const filtersCopy = [...filters];

    if (process.env.REACT_APP_HAS_TAG === '1') {
      filtersCopy.push(commonStore.alert);
    }
    return filtersCopy;
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

  const Component = filtersAreSticky ? Affix : Static;

  return (
    <Component offsetTop={10}>
      <UICard style={{ marginBottom: '10px' }}>
        <FilterContainer>
          <div>
            <Title>
              Filters{' '}
              {filtersAreSticky ? (
                <PushpinFilled onClick={() => dispatch(ruleSetsActions.toggleStickyFilters())} />
              ) : (
                <PushpinOutlined onClick={() => dispatch(ruleSetsActions.toggleStickyFilters())} />
              )}
            </Title>
            <div style={{ display: 'flex', flex: 1, gap: 8 }}>
              <FiltersSelector id="filters" data-test="filters-dropdown">
                <Tooltip title={page === 'HOST_INSIGHT' ? 'Filters are not applicable' : null}>
                  <CascaderStyled
                    data-test="filters-cascader-menu"
                    disabled={page === 'HOST_INSIGHT'}
                    value={selectedIds}
                    options={treeOptions}
                    displayRender={displayRender}
                    onChange={value => onChange(value)}
                    getPopupContainer={() => document.getElementById('filters')}
                  />
                </Tooltip>
              </FiltersSelector>
              {field && filterType !== 'complex-select' && filterType !== 'select' && (
                <div style={{ display: 'flex', flex: 1, flexDirection: 'column' }}>
                  <Input
                    data-test="filter-input-field"
                    type={filterType === 'number' ? 'number' : 'text'}
                    value={searchString}
                    onChange={e => {
                      validate(valueType, e.target.value);
                      setSearchString(e.target.value);
                    }}
                    placeholder={placeholder}
                    onPressEnter={event => {
                      const { value: raw = '' } = event.target;
                      const value = filterType === 'number' && raw.length > 0 ? parseInt(raw, 10) : raw;
                      if (valid.length === 0 && ((value && typeof value === 'string' && value.length > 0) || typeof value === 'number')) {
                        filterAdded(field, value, false);
                      }
                    }}
                  />
                  <FilterError>{valid}</FilterError>
                </div>
              )}
              {filterType === 'complex-select' && filterCategory && (
                <Select
                  style={{ width: 200 }}
                  showSearch
                  placeholder={field && field.placeholder}
                  optionFilterProp="children"
                  onChange={value => {
                    filterAdded(field, value, true);
                  }}
                  filterOption={(input, option) => option.children.toLowerCase().includes(input.toLowerCase())}
                  data-test="filters-dropdown-two"
                >
                  {filterCategory && filterCategory.filterValues.map(v => <Option value={v.id}>{v.label}</Option>)}
                </Select>
              )}
            </div>
            <Divider style={{ margin: '15px 0' }} />
            <Row>
              <Col md={24}>
                {activeFilters && activeFilters.length > 0 && <FilterList page={page} filters={activeFilters} filterType={section} />}
              </Col>
            </Row>
          </div>
          <Space direction="vertical">
            {page !== 'HISTORY' && <AdditionalFilters page={page} />}
            {/* 'INVENTORY' should be included when backend is fixed */}
            {['RULES_LIST', 'HOSTS_LIST', 'HISTORY'].indexOf(page) > -1 && (
              <Sort page={page} onChange={(option, direction) => onSortChange(option, direction)} value={sortValues} />
            )}
          </Space>
          {page !== 'HISTORY' && commonStore.systemSettings.license?.nta && (
            <div>
              <Title>Tags Filters</Title>
              <Space direction="vertical">
                <Space>
                  <UISwitch
                    activeBackgroundColor="#7b1244"
                    size="small"
                    checkedChildren="ON"
                    unCheckedChildren="OFF"
                    checked={commonStore.alert.value.informational}
                    onChange={() => {
                      commonStore.toggleAlertTag('informational');
                    }}
                    disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}
                    data-test="Informational-switch"
                  />
                  <UISwitchLabel disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}>Informational</UISwitchLabel>
                </Space>
                <Space>
                  <UISwitch
                    activeBackgroundColor="#ec7a08"
                    size="small"
                    checkedChildren="ON"
                    unCheckedChildren="OFF"
                    checked={commonStore.alert.value.relevant}
                    onChange={() => {
                      commonStore.toggleAlertTag('relevant');
                    }}
                    disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}
                    data-test="Relevant-switch"
                  />
                  <UISwitchLabel disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}>Relevant</UISwitchLabel>
                </Space>
                <Space>
                  <Switch
                    size="small"
                    checkedChildren="ON"
                    unCheckedChildren="OFF"
                    checked={commonStore.alert.value.untagged}
                    onChange={() => {
                      commonStore.toggleAlertTag('untagged');
                    }}
                    disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}
                    data-test="Untagged-switch"
                  />
                  <UISwitchLabel disabled={page === 'HOST_INSIGHT' || page === 'INVENTORY'}>Untagged</UISwitchLabel>
                </Space>
              </Space>
            </div>
          )}
          {page !== 'HISTORY' && <Separator />}
          {page !== 'HISTORY' && <Actions section={section} />}
        </FilterContainer>
        {saveFiltersModal && (
          <FilterSetSaveModal
            title="Create new Filter Set"
            close={() => {
              dispatch(ruleSetsActions.saveFiltersModal(false));
            }}
            fromPage={page}
            content={getFiltersCopy()}
          />
        )}
      </UICard>
    </Component>
  );
};

Filter.propTypes = {
  page: PropTypes.oneOf(['RULES_LIST', 'DASHBOARDS', 'ALERTS_LIST', 'HISTORY', 'HOSTS_LIST', 'INVENTORY']),
  section: PropTypes.string.isRequired,
  queryTypes: PropTypes.array.isRequired,
  filterTypes: PropTypes.array.isRequired,
  onSortChange: PropTypes.func.isRequired,
  sortValues: PropTypes.shape({
    option: PropTypes.string,
    direction: PropTypes.string,
  }),
};

export default observer(Filter);
