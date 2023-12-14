import React, { useCallback, useEffect, useMemo, useState } from 'react';
import styled from 'styled-components';
import { Cascader, Input, message, Switch, Tooltip } from 'antd';
import FilterValueType from 'ui/maps/FilterValueType';
import Filter from 'ui/utils/Filter';
import { useStore } from 'ui/mobx/RootStoreProvider';
import capitalize from 'ui/helpers/capitalize';
import PropTypes from 'prop-types';
import isIP from 'ui/helpers/isIP';
import FilterValidationType from 'ui/maps/FilterValidationType';
import { FilterCategory } from 'ui/maps/Filters';
import FiltersDropdownItems from 'ui/maps/FiltersDropdownItems';
import useNetworkDefs from 'ui/hooks/useNetworkDefs';
import useHistoryFilters from 'ui/hooks/useHistoryFilters';
import formatDropdownItem from 'ui/helpers/formatDropdownItem';

const CascaderStyled = styled(Cascader)`
  width: max-content;
  position: relative;
  line-height: 2.2715;
  min-width: 200px;

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
    max-height: 580px;
    min-width: 200px;
  }
  & .ant-cascader-menu-item-disabled {
    cursor: default;
    background-color: #e2e2e2 !important;
    color: #5a5a5a;
    text-shadow: 0 1px #fff;
    font-weight: bold;
  }
`;

const getSelectedItem = items => {
  // The element before the last one
  const beforeLast = items.length > 1 ? items[items.length - 2] : null;

  // The last element
  const last = items[items.length > 0 ? items.length - 1 : 0];

  if (beforeLast?.valueType === FilterValueType.SELECT) {
    return {
      // SELECT types don't have validation types
      selectedValueType: FilterValueType.SELECT,
      selectedCategory: beforeLast.category,
    };
  }
  return {
    selectedValidationType: last.validationType,
    selectedValueType: last.valueType || FilterValueType.TEXT,
    selectedCategory: last.category || FilterCategory.EVENT,
  };
};

function FiltersDropdown({ disabled, filterTypes }) {
  const { commonStore } = useStore();
  const networkDefs = useNetworkDefs();
  const historyFilters = useHistoryFilters();

  const [pathItems, setPathItems] = useState({ path: null, items: [] });
  const [negated, setNegated] = useState(false);
  const [value, setValue] = useState();
  const [valueType, setValueType] = useState();
  const [validationType, setValidationType] = useState();

  const onClear = () => {
    setValueType();
    setValue();
    setNegated(false);
  };

  const onChangeHandler = (path, items) => {
    if (!path) {
      onClear();
      return;
    }
    setPathItems({ path, items });
  };

  useEffect(() => {
    const { path, items } = pathItems;
    if (path) {
      const { selectedValueType, selectedCategory, selectedValidationType } = getSelectedItem(items);
      if (selectedValueType === FilterValueType.SELECT) {
        // Filter value is always the last selected option
        const filterValue = path[path.length - 1];
        // Filter ID is always the one right before the last one
        const filterId = (path.length > 1 ? path[path.length - 2] : path[0]).replace(/:value-id-\d+/, '');
        if (selectedCategory === FilterCategory.HISTORY) {
          commonStore.addHistoryFilter(new Filter(filterId, filterValue, { fullString: true }));
        } else {
          commonStore.addFilter(new Filter(filterId, filterValue, selectedCategory, { negated: false }));
        }
        onClear();
        return;
      }

      setValidationType(selectedValidationType);
      setValueType(selectedValueType);
      setValue(path);
    }
  }, [pathItems]);

  const onSubmit = e => {
    const { selectedCategory } = getSelectedItem(pathItems.items);
    const filterId = value.length > 1 ? value[value.length - 1] : value[0];
    let inputValue = e.target.value;

    // Value sanitization
    switch (valueType) {
      case FilterValueType.NUMBER:
        inputValue = parseInt(e.target.value, 10);
        break;
      case FilterValueType.TEXT:
        inputValue = e.target.value.trim();
        break;
      default:
        break;
    }

    /* Validation */
    if (valueType === FilterValueType.TEXT && inputValue.length === 0) {
      message.error({ content: "The filter value can't be empty" });
      return;
    }
    if (validationType) {
      if (validationType === FilterValidationType.POSITIVE_INT && (inputValue < 0 || Number.isNaN(inputValue))) {
        message.error({ content: 'The filter value must be a positive integer' });
        return;
      }
      if (validationType === FilterValidationType.IP && !isIP(inputValue)) {
        message.error({ content: 'The filter value must be a valid IP address' });
        return;
      }
    }

    /* Is Regex ? */
    if (selectedCategory === FilterCategory.HISTORY) {
      commonStore.addHistoryFilter(new Filter(filterId, inputValue, { fullString: false }));
    } else {
      /* alert.signature edge case */
      const alertSignature = filterId === 'alert.signature' ? { fullString: false } : {};
      commonStore.addFilter(new Filter(filterId, inputValue, selectedCategory, { negated, ...alertSignature }));
    }
    onClear();
  };

  const makeFilterCategory = useCallback(
    name => ({
      value: name,
      label: `${capitalize(name.toLowerCase())} filters`,
      disabled: true,
    }),
    [FiltersDropdownItems],
  );

  const options = useMemo(() => {
    let result = [];
    const categories = Object.keys(FiltersDropdownItems).filter(c => filterTypes.includes(c));
    categories.forEach(category => {
      const items = FiltersDropdownItems[category].map(c => formatDropdownItem({ ...c, category }));
      result = [
        /* Inherit */
        ...result,
        /* Create category item */
        makeFilterCategory(category),
        /* Append Network Defs filters in case there are any */
        ...(category === 'EVENT' ? networkDefs : []),
        /* Append History filters  */
        ...(category === 'HISTORY' ? historyFilters : []),
        /* Append filters */
        ...items,
      ];
    });
    return result;
  }, [FiltersDropdownItems, filterTypes, networkDefs]);

  const placeholder = useMemo(() => {
    let result = 'Enter ';
    if (validationType) {
      switch (validationType) {
        case FilterValidationType.IP:
          result += 'IP address';
          break;
        case FilterValidationType.POSITIVE_INT:
          result += 'a number';
          break;
        default:
          break;
      }
    } else {
      switch (valueType) {
        case FilterValueType.TEXT:
          result += 'filter text';
          break;
        case FilterValueType.NUMBER:
          result += 'a number';
          break;
        default:
          break;
      }
    }
    return result;
  }, [validationType, valueType]);

  const filter = (inputValue, path) => path.some(option => option.title?.toLowerCase().indexOf(inputValue.toLowerCase()) > -1);

  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
      <FiltersSelector id="filters" data-test="filters-dropdown">
        <Tooltip title={!options || disabled ? 'Filters are not applicable' : null}>
          <CascaderStyled
            value={value}
            disabled={disabled}
            data-test="filters-cascader-menu"
            onChange={onChangeHandler}
            options={options}
            getPopupContainer={() => document.getElementById('filters')}
            showSearch={{ filter, matchInputWidth: false }}
          />
        </Tooltip>
      </FiltersSelector>
      {valueType === FilterValueType.TEXT && (
        <div>
          <Switch
            data-test="initialy-negated"
            checkedChildren={<span>IS</span>}
            unCheckedChildren={<span>NOT</span>}
            size="default"
            onChange={n => setNegated(!n)}
            value={negated}
            defaultChecked
          />
        </div>
      )}
      {valueType === FilterValueType.TEXT && <Input type="text" onPressEnter={onSubmit} placeholder={placeholder} data-test="filter-input-field" />}
      {valueType === FilterValueType.NUMBER && (
        <Input type="number" onPressEnter={onSubmit} placeholder={placeholder} data-test="filter-input-field" />
      )}
    </div>
  );
}

export default FiltersDropdown;

FiltersDropdown.propTypes = {
  disabled: PropTypes.bool,
  filterTypes: PropTypes.arrayOf(PropTypes.string),
};
