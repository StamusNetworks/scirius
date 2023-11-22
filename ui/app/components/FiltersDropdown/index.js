import React, { useMemo, useState } from 'react';
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
    max-height: 560px;
    min-width: 200px;
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

const FiltersDropdown = ({ disabled, filterTypes }) => {
  const { commonStore } = useStore();

  const [negated, setNegated] = useState(false);
  const [value, setValue] = useState();
  const [category, setCategory] = useState();
  const [valueType, setValueType] = useState();
  const [validationType, setValidationType] = useState();

  const onClear = () => {
    setValueType();
    setValue();
    setCategory();
    setNegated(false);
  };

  const onChangeHandler = (path, items) => {
    if (!path) {
      onClear();
      return;
    }

    const { selectedValueType, selectedCategory, selectedValidationType } = getSelectedItem(items);
    if (selectedValueType === FilterValueType.SELECT) {
      // Filter value is always the last selected option
      const filterValue = path[path.length - 1];
      // Filter ID is always the one right before the last one
      const filterId = path.length > 1 ? path[path.length - 2] : path[0];
      if (selectedCategory === FilterCategory.HISTORY) {
        commonStore.addHistoryFilter(new Filter(filterId, filterValue, { fullString: true }));
      } else {
        commonStore.addFilter(new Filter(filterId, filterValue, selectedCategory, { negated: false }));
      }
      onClear();
      return;
    }

    setValidationType(selectedValidationType);
    setCategory(selectedCategory);
    setValueType(selectedValueType);
    setValue(path);
  };

  const onSubmit = e => {
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
    const exactMatch = valueType !== FilterValueType.NUMBER ? !/[\\*?]/.test(inputValue) : true;
    commonStore.addFilter(new Filter(filterId, inputValue, category, { negated, fullString: exactMatch }));
    onClear();
  };

  const options = useMemo(
    () =>
      filterTypes
        ?.map(f => [
          {
            value: f,
            label: `${capitalize(f.toLowerCase())} filters`,
            disabled: true,
          },
          ...FiltersDropdownItems[f],
        ])
        .flat(),
    [...(filterTypes || [])],
  );

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
};

export default FiltersDropdown;

FiltersDropdown.propTypes = {
  disabled: PropTypes.bool,
  filterTypes: PropTypes.arrayOf(PropTypes.string),
};
