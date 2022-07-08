/* eslint-disable react/sort-comp,no-else-return,react/no-access-state-in-setstate */
/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { Button, Switch, Menu, Dropdown } from 'antd';
import { DownOutlined } from '@ant-design/icons';
// import { Shortcuts } from 'react-shortcuts';
import Select from 'react-select';
import axios from 'axios';
import { compose } from 'redux';
import * as config from 'config/Api';
import { huntTabs, sections } from 'ui/constants';
import { HuntSort } from 'ui/Sort';
import ErrorHandler from 'ui/components/Error';
import FilterList from 'ui/components/FilterList/index';
import FilterSetSave from 'ui/components/FilterSetSaveModal';
import FilterSets from 'ui/components/FilterSets';
import {
  makeSelectGlobalFilters,
  makeSelectAlertTag,
  makeSelectHistoryFilters,
  addFilter,
  clearFilters,
  setTag,
  enableOnly,
} from 'ui/containers/HuntApp/stores/global';
import { loadFilterSets } from 'ui/components/FilterSets/store';
import { withPermissions } from 'ui/containers/HuntApp/stores/withPermissions';
import './HuntFilter.css';

// https://www.regextester.com/104038
const IP_REGEXP =
  /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;

function isIpOrNetwork(ip) {
  let ipAddress = ip;

  const prefixIdx = ip.indexOf('/');
  if (prefixIdx !== -1) {
    const prefix = ip.substr(prefixIdx + 1);
    if (parseInt(prefix, 10).toString() !== prefix) {
      return false;
    }
    ipAddress = ip.substr(0, prefixIdx);
  }
  return IP_REGEXP.test(ipAddress);
}

class HuntFilter extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      // eslint-disable-next-line react/no-unused-state
      filterFields: this.props.filterFields,
      currentFilterType: this.props.filterFields[0] || {},
      currentValue: '',
      filterSets: { showModal: false, shared: false, description: '' },
      filterSetName: '',
      errors: undefined,
      showNotifications: false,
    };
    this.loadHuntFilterSetsModal = this.loadHuntFilterSetsModal.bind(this);
    this.setSharedFilter = this.setSharedFilter.bind(this);
    this.closeHuntFilterSetsModal = this.closeHuntFilterSetsModal.bind(this);
    this.toggleHuntFilterSetsModal2 = this.toggleHuntFilterSetsModal2.bind(this);
    this.closeHuntFilterSetsModal2 = this.closeHuntFilterSetsModal2.bind(this);
    this.submitFilterSets = this.submitFilterSets.bind(this);
    this.handleFieldChange = this.handleFieldChange.bind(this);
    this.handleDescriptionChange = this.handleDescriptionChange.bind(this);
    this.setViewType = this.setViewType.bind(this);
  }

  componentDidUpdate(prevProps) {
    if (prevProps.filterFields !== this.props.filterFields && this.state.currentFilterType === undefined) {
      // eslint-disable-next-line react/no-did-update-set-state
      this.setState({ currentFilterType: this.props.filterFields[0] });
    }
  }

  onValueKeyPress = keyEvent => {
    const { currentValue, currentFilterType } = this.state;

    if (keyEvent.key === 'Enter') {
      if (currentValue && currentValue.length > 0) {
        // remove empty spaces from the filter string start/end
        this.setState({ currentValue: currentValue.trim() });

        if (currentFilterType.valueType === 'positiveint') {
          const val = parseInt(currentValue, 10);
          if (val >= 0) {
            this.setState({ currentValue: '' });
            this.filterAdded(currentFilterType, val, true);
          } else {
            // Propagate event to trigger validation error
            return;
          }
        } else if (currentFilterType.valueType === 'ip') {
          if (isIpOrNetwork(currentValue)) {
            this.setState({ currentValue: '' });
            this.filterAdded(currentFilterType, currentValue, true);
          }
        } else {
          this.setState({ currentValue: '' });
          this.filterAdded(currentFilterType, currentValue, false);
        }
      }
      keyEvent.stopPropagation();
      keyEvent.preventDefault();
    }
  };

  filterAdded = (field, value, fullString) => {
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
      if (this.state.filterSubCategory) {
        filterText = `${this.state.filterCategory.id}.${this.state.filterSubCategory.id}`;
      } else {
        filterText = `${this.state.filterCategory.id}`;
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
    this.props.addFilter(this.props.filterType, {
      label: filterText,
      id: fieldId,
      value: fvalue,
      negated: false,
      query: field.queryType,
      fullString,
    });
  };

  selectFilterType = filterType => {
    const { currentFilterType } = this.state;
    if (currentFilterType !== filterType) {
      this.setState(prevState => ({
        currentValue: '',
        currentFilterType: filterType,
        filterCategory: filterType.filterType.includes('complex-select') ? undefined : prevState.filterCategory,
        categoryValue: filterType.filterType.includes('complex-select') ? '' : prevState.categoryValue,
      }));
    }
  };

  selectFilterValue = filterValue => {
    const { currentFilterType, currentValue } = this.state;

    if (filterValue !== currentValue) {
      this.setState({ currentValue: filterValue });
      if (filterValue) {
        this.filterAdded(currentFilterType, filterValue, true);
      }
    }
  };

  filterCategorySelected = category => {
    const { filterCategory } = this.state;
    if (filterCategory !== category) {
      this.setState({ filterCategory: category, filterSubCategory: undefined, currentValue: '' });
    }
  };

  filterSubCategorySelected = category => {
    const { filterSubCategory } = this.state;
    if (filterSubCategory !== category) {
      this.setState({ filterSubCategory: category, currentValue: '' });
    }
  };

  categoryValueSelected = value => {
    const { currentValue, currentFilterType, filterCategory } = this.state;

    if (filterCategory && currentValue !== value) {
      this.setState({ currentValue: value });
      if (value) {
        const filterValue = {
          filterCategory,
          filterValue: value,
        };
        this.filterAdded(currentFilterType, filterValue, true);
      }
    }
  };

  updateCurrentValue = event => {
    const { currentFilterType } = this.state;
    let error = false;
    let { value } = event.target;

    if (currentFilterType.valueType === 'ip') {
      // not allow empty spaces anywhere in the IP while typing it
      value = value.trim();
      const numbers = value.split(/\.|:|\//);
      const filteredNum = numbers.filter(item => item !== '');

      const UINT_REGEXP_V4 = /^\d*[0-9]\d*$/;
      const UINT_REGEXP_V6 = /[0-9a-fA-F]{1,4}/;
      for (let idx = 0; idx < filteredNum.length; idx += 1) {
        if (!UINT_REGEXP_V4.test(filteredNum[idx]) && !UINT_REGEXP_V6.test(filteredNum[idx])) {
          error = true;
          break;
        }
      }
    } else if (
      ['msg', 'not_in_msg', 'content', 'es_filter', 'not_in_content'].indexOf(this.state.currentFilterType.id) === -1 &&
      value.indexOf(' ') !== -1
    ) {
      // No space allowed to avoid breaking ES queries
      error = true;
    }
    if (!error) this.setState({ currentValue: event.target ? value : event /* used by Select component */ });
  };

  getValidationState = () => {
    const { currentFilterType, currentValue, filterSubCategory } = this.state;
    let { valueType } = currentFilterType;

    if (typeof filterSubCategory !== 'undefined' && filterSubCategory.valueType) {
      ({ valueType } = filterSubCategory);
    }

    if (valueType === 'positiveint') {
      const val = parseInt(currentValue, 10);
      if (val >= 0) {
        return 'success';
      } else {
        return 'error';
      }
    } else if (valueType === 'ip') {
      if (!isIpOrNetwork(currentValue)) {
        return 'error';
      }
      return 'success';
    }
    return null;
  };

  handleShortcuts = action => {
    switch (action) {
      case 'SSP_UNTAGGED': {
        this.props.enableOnly('untagged');
        break;
      }
      case 'SSP_INFORMATIONAL': {
        this.props.enableOnly('informational');
        break;
      }
      case 'SSP_RELEVANT': {
        this.props.enableOnly('relevant');
        break;
      }
      case 'SSP_ALERTS': {
        this.props.enableOnly('alerts');
        break;
      }
      case 'SSP_SIGHTINGS': {
        this.props.enableOnly('sightings');
        break;
      }
      case 'SSP_ALL': {
        this.props.enableOnly('all');
        break;
      }
      default:
        break;
    }
  };

  closeHuntFilterSetsModal() {
    this.setState({ filterSets: { showModal: false, shared: false, description: '' } });
  }

  closeHuntFilterSetsModal2() {
    if (this.state.showNotifications) {
      this.setState({ showNotifications: false });
    }
  }

  toggleHuntFilterSetsModal2() {
    this.setState(prevState => ({
      showNotifications: !prevState.showNotifications,
    }));
  }

  loadHuntFilterSetsModal() {
    this.setState({ filterSets: { showModal: true, shared: false } });
  }

  setSharedFilter(e) {
    this.setState({ filterSets: { showModal: true, shared: e.target.checked, description: this.state.filterSets.description } });
  }

  renderInput() {
    // eslint-disable-next-line no-unused-vars
    const { currentFilterType, currentValue, filterCategory, filterSubCategory } = this.state;
    if (!currentFilterType) {
      return null;
    }

    if (currentFilterType.filterType === 'select') {
      return null;
      /*
        <Filter.ValueSelector
          filterValues={currentFilterType.filterValues}
          placeholder={currentFilterType.placeholder}
          currentValue={currentValue}
          onFilterValueSelected={this.selectFilterValue}
        />
        */
    } else if (currentFilterType.filterType === 'complex-select') {
      const customStyles = {
        option: (provided, state) => ({
          ...provided,
          color: state.isSelected ? null : 'black',
          backgroundColor: state.isFocused ? '#dcc6c5' : null,
          ':active': {
            backgroundColor: state.isSelected ? null : '#7b1244',
            color: state.isSelected ? null : 'white',
          },
        }),
        container: provided => ({
          ...provided,
          display: 'inline-block',
          width: '250px',
          minHeight: '1px',
          textAlign: 'left',
          border: 'none',
          zIndex: '1000',
        }),
        control: (provided, state) => ({
          ...provided,
          border: state.isFocused ? '1px solid #9c9c9c' : '1px solid #bbb',
          boxShadow: state.isFocused ? null : null,
          '&:hover': {
            border: state.isFocused ? '1px solid #9c9c9c' : '1px solid #bbb',
            backgroundColor: '#e8e8e8',
            color: 'yellow',
          },
          borderRadius: '0',
          minHeight: '1px',
          height: '26px',
          cursor: 'pointer',
        }),
        input: provided => ({
          ...provided,
          minHeight: '1px',
        }),
        dropdownIndicator: provided => ({
          ...provided,
          minHeight: '1px',
          paddingTop: '0',
          paddingBottom: '5',
          color: '#8b8d8f',
        }),
        indicatorSeparator: provided => ({
          ...provided,
          minHeight: '1px',
          height: '12px',
        }),
        valueContainer: provided => ({
          ...provided,
          minHeight: '1px',
          height: '25px',
          paddingTop: '0',
          paddingBottom: '0',
          position: 'static !important',
          fontWeight: 600,
        }),
        singleValue: provided => ({
          ...provided,
          minHeight: '1px',
          paddingBottom: '2px',
        }),
      };

      if (currentFilterType.filterCategories) {
        return null;
        /*
          <Filter.CategorySelector
            filterCategories={currentFilterType.filterCategories}
            currentCategory={filterCategory}
            placeholder={currentFilterType.placeholder}
            onFilterCategorySelected={this.filterCategorySelected}
          >
            {filterCategory && (
              <Select
                styles={customStyles}
                value={currentValue}
                options={filterCategory && filterCategory.filterValues}
                onChange={this.selectFilterValue}
                className="basic-single toolbar-pf-filter"
                classNamePrefix="select"
                placeholder={currentFilterType.sub_placeholder}
              />
            )}
          </Filter.CategorySelector>
        */
      } else {
        return (
          <Select
            styles={customStyles}
            value={currentValue}
            options={currentFilterType && currentFilterType.filterValues}
            onChange={this.selectFilterValue}
            className="basic-single toolbar-pf-filter"
            classNamePrefix="select"
            placeholder={currentFilterType.sub_placeholder}
          />
        );
      }
    } else if (currentFilterType.filterType === 'complex-select-text') {
      return null;
      /*
        <Filter.CategorySelector
          filterCategories={currentFilterType.filterCategories}
          currentCategory={filterCategory}
          placeholder={currentFilterType.placeholder}
          onFilterCategorySelected={this.filterCategorySelected}
        >
          {filterCategory && filterCategory.valueType === undefined && (
            <Filter.CategorySelector
              filterCategories={filterCategory && filterCategory.filterValues}
              currentCategory={filterSubCategory}
              placeholder={currentFilterType.filterCategoriesPlaceholder}
              onFilterCategorySelected={this.filterSubCategorySelected}
            />
          )}
          {filterCategory && filterSubCategory && (
            <FormGroup controlId="input-filter" validationState={this.getValidationState()} data-test="hunt-filter__input">
              <FormControl
                type={filterSubCategory.filterType}
                value={currentValue}
                placeholder={filterSubCategory.placeholder}
                onChange={(e) => this.updateCurrentValue(e)}
                onKeyPress={(e) => this.onValueKeyPress(e)}
              />
            </FormGroup>
          )}
          {filterCategory && filterCategory.valueType && (
            <FormGroup controlId="input-filter" validationState={this.getValidationState()} data-test="hunt-filter__input">
              <FormControl
                type={currentFilterType.filterType}
                value={currentValue}
                placeholder={filterCategory.placeholder}
                onChange={(e) => this.updateCurrentValue(e)}
                onKeyPress={(e) => this.onValueKeyPress(e)}
              />
            </FormGroup>
          )}
        </Filter.CategorySelector>
        */
    } else if (currentFilterType.valueType === 'positiveint') {
      return null;
      /*
        <FormGroup controlId="input-filter" validationState={this.getValidationState()} data-test="hunt-filter__input">
          <FormControl
            type={currentFilterType.filterType}
            value={currentValue}
            min={0}
            placeholder={currentFilterType.placeholder}
            onChange={(e) => this.updateCurrentValue(e)}
            onKeyPress={(e) => this.onValueKeyPress(e)}
          />
        </FormGroup>
        */
    }
    return null;
    /*
      <FormGroup controlId="input-filter" validationState={this.getValidationState()} data-test="hunt-filter__input">
        <FormControl
          type={currentFilterType.filterType}
          value={currentValue}
          placeholder={currentFilterType.placeholder}
          onChange={(e) => this.updateCurrentValue(e)}
          onKeyPress={(e) => this.onValueKeyPress(e)}
        />
      </FormGroup>
    */
  }

  handleFieldChange(event) {
    this.setState({
      filterSetName: event.target.value,
      filterSets: { showModal: true, shared: this.state.filterSets.shared, description: this.state.filterSets.description },
    });
  }

  handleDescriptionChange(event) {
    this.setState({
      filterSetName: this.state.filterSetName,
      filterSets: { showModal: true, shared: this.state.filterSets.shared, description: event.target.value },
    });
  }

  submitFilterSets() {
    this.setState({ errors: undefined });

    const filters = [...this.props.filters];

    if (process.env.REACT_APP_HAS_TAG === '1') {
      filters.push(this.props.alertTag);
    }

    axios
      .post(config.API_URL + config.HUNT_FILTER_SETS, {
        name: this.state.filterSetName,
        page: this.props.page,
        content: filters,
        share: this.state.filterSets.shared,
        description: this.state.filterSets.description,
      })
      .then(() => {
        this.props.loadFilterSets();
        this.closeHuntFilterSetsModal();
        this.setState({ errors: undefined });
      })
      .catch(error => {
        let errors = error.response.data;

        if (error.response.status === 403) {
          const noRights = this.props.user.isActive && !this.props.user.permissions.includes('rules.events_edit') && this.state.filterSets.shared;
          if (noRights) {
            errors = { permission: ['Insufficient permissions. "Shared" is not allowed.'] };
          }
        }
        this.setState({ errors });
      });
  }

  renderInputHuntFilterSetsModal() {
    let { page } = this.props;
    page = huntTabs[page];

    const noRights = this.props.user.isActive && !this.props.user.permissions.includes('rules.events_edit');
    return (
      <FilterSetSave
        title="Create new Filter Set"
        showModal={this.state.filterSets.showModal}
        close={this.closeHuntFilterSetsModal}
        errors={this.state.errors}
        handleDescriptionChange={this.handleDescriptionChange}
        handleComboChange={undefined}
        handleFieldChange={this.handleFieldChange}
        setSharedFilter={this.setSharedFilter}
        submit={this.submitFilterSets}
        page={page}
        noRights={noRights}
      />
    );
  }

  setViewType(type) {
    this.props.itemsListUpdate({
      ...this.props.config,
      view_type: type,
    });
  }

  render() {
    const { currentFilterType } = this.state;
    const activeFilters = [];
    const filters = this.props.filterType === sections.HISTORY ? this.props.historyFilters : this.props.filters;
    filters.forEach(item => {
      if (item.query === undefined || this.props.queryType.indexOf(item.query) !== -1) {
        activeFilters.push(item);
      }
    });
    const menuFilters = [];
    this.props.filterFields.forEach(item => {
      if (item.filterType !== 'hunt') {
        menuFilters.push(item);
      }
    });

    const menu = (
      <Menu onClick={e => this.selectFilterType(menuFilters.find(item => item.id === e.key))} selectedKeys={[currentFilterType.title]}>
        {menuFilters.map(item => (
          <Menu.Item key={item.id}>
            <a href="#" data-test={`filter-main-dropdown-${item.title}`}>
              {item.title}
            </a>
          </Menu.Item>
        ))}
      </Menu>
    );

    return (
      <div>
        {this.state.showNotifications && (
          <ErrorHandler>
            <FilterSets close={this.closeHuntFilterSetsModal2} />
          </ErrorHandler>
        )}
        {/* <Shortcuts name="HUNT_FILTER" handler={this.handleShortcuts} isolate targetNodeSelector="body"> */}
        <div className="hunt-filter__container" data-test="hunt-filter__container">
          <div className="hunt-filter__filters">
            <h4>Filters</h4>
            <div className="hunt-filter__filters--1">
              {/* <Filter.TypeSelector filterTypes={menuFilters} currentFilterType={currentFilterType} onFilterTypeSelected={this.selectFilterType} /> */}
              <Dropdown overlay={menu} trigger={['click']}>
                <Button data-test="filter-main-dropdown">
                  <span data-test={`filter-main-dropdown__${currentFilterType.title}`}>{currentFilterType.title}</span> <DownOutlined />
                </Button>
              </Dropdown>
              {this.renderInput()}
            </div>
            <div className="hunt-filter__filters--3">
              {this.props.sort_config && this.props.config && (
                <HuntSort
                  config={this.props.sort_config}
                  itemsList={this.props.config}
                  itemsListUpdate={this.props.itemsListUpdate}
                  disabled={this.props.disable_sort ? this.props.disable_sort : false}
                />
              )}
              {this.props.displayToggle && (
                <div>
                  <Button
                    title="List View"
                    type="text"
                    className={{ active: this.props.config.view_type === 'list' }}
                    onClick={() => {
                      this.setViewType('list');
                    }}
                  >
                    TH-LIST
                    {/* <Icon type="fa" name="th-list" /> */}
                  </Button>
                  <Button
                    title="Card View"
                    type="text"
                    className={{ active: this.props.config.view_type === 'card' }}
                    onClick={() => {
                      this.setViewType('card');
                    }}
                  >
                    TH
                    {/* <Icon type="fa" name="th" /> */}
                  </Button>
                </div>
              )}
            </div>
            {activeFilters && activeFilters.length > 0 && (
              <div className="hunt-filter__filters--2">
                <FilterList filters={activeFilters} filterType={this.props.filterType} />
              </div>
            )}
          </div>

          {this.props.gotAlertTag && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && (
            <div className="hunt-filter__tags-filters">
              <h4>Tags Filters</h4>
              <div>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={this.props.alertTag.value.informational}
                  // onColor="info"
                  // value={this.props.alertTag.value.informational}
                  onChange={() => this.props.setTag('informational', !this.props.alertTag.value.informational)}
                  data-test="filter-tag-informational"
                />
                <span>Informational</span>
              </div>
              <div>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={this.props.alertTag.value.relevant}
                  // onColor="warning"
                  // value={this.props.alertTag.value.relevant}
                  onChange={() => this.props.setTag('relevant', !this.props.alertTag.value.relevant)}
                  data-test="filter-tag-relevant"
                />
                <span>Relevant</span>
              </div>
              <div>
                <Switch
                  size="small"
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  defaultChecked={this.props.alertTag.value.untagged}
                  // onColor="primary"
                  // value={this.props.alertTag.value.untagged}
                  onChange={() => this.props.setTag('untagged', !this.props.alertTag.value.untagged)}
                  data-test="filter-tag-untagged"
                />
                <span>Untagged</span>
              </div>
            </div>
          )}

          <div className="hunt-filter__actions">
            <h4>Actions</h4>
            <div
              data-toggle="tooltip"
              data-placement="top"
              data-test="clear-filters"
              title="Clear All Filters"
              id="clear"
              role="button"
              onClick={() => {
                this.props.clearFilters(this.props.filterType);
              }}
              style={{ cursor: 'pointer' }}
            >
              <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                <path d="M0 0h24v24H0V0z" fill="none" />
                <path d="M5 13h14v-2H5v2zm-2 4h14v-2H3v2zM7 7v2h14V7H7z" />
              </svg>
              <span>Clear Filters</span>
            </div>
            <div
              tabIndex={0}
              data-toggle="tooltip"
              title="Filter Sets"
              onClick={() => {
                this.toggleHuntFilterSetsModal2();
              }}
              role="button"
              style={{ cursor: 'pointer' }}
            >
              <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                <path d="M0 0h24v24H0V0z" fill="none" />
                <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z" />
              </svg>
              <span>Load Filter Set</span>
            </div>
            {this.props.page !== 'HISTORY' && (
              <div
                data-toggle="tooltip"
                data-placement="top"
                title="Save Filter Set"
                id="saveall"
                role="button"
                onClick={() => {
                  this.loadHuntFilterSetsModal();
                }}
                style={{ cursor: 'pointer' }}
              >
                <svg enableBackground="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
                  <g>
                    <rect fill="none" height="24" width="24" />
                  </g>
                  <g>
                    <path d="M14,10H3v2h11V10z M14,6H3v2h11V6z M18,14v-4h-2v4h-4v2h4v4h2v-4h4v-2H18z M3,16h7v-2H3V16z" />
                  </g>
                </svg>
                <span>Save Filter Set</span>
              </div>
            )}
            {this.props.actionsButtons && this.props.actionsButtons()}
          </div>
        </div>
        {this.renderInputHuntFilterSetsModal()}
        {/* </Shortcuts> */}
      </div>
    );
  }
}

HuntFilter.defaultProps = {
  filterType: sections.GLOBAL,
  displayToggle: false,
  gotAlertTag: true,
};

HuntFilter.propTypes = {
  filterFields: PropTypes.any,
  gotAlertTag: PropTypes.bool,
  queryType: PropTypes.any,
  sort_config: PropTypes.any,
  disable_sort: PropTypes.any,
  itemsListUpdate: PropTypes.any,
  config: PropTypes.any,
  actionsButtons: PropTypes.any,
  displayToggle: PropTypes.bool,
  page: PropTypes.any,
  setTag: PropTypes.func,
  enableOnly: PropTypes.func,
  clearFilters: PropTypes.func,
  addFilter: PropTypes.func,
  filterType: PropTypes.string,
  alertTag: PropTypes.shape({
    value: PropTypes.shape({
      informational: PropTypes.bool,
      relevant: PropTypes.bool,
      untagged: PropTypes.bool,
      alerts: PropTypes.bool,
      sightings: PropTypes.bool,
    }),
  }),
  loadFilterSets: PropTypes.func,
  filters: PropTypes.array,
  historyFilters: PropTypes.array,
  user: PropTypes.shape({
    pk: PropTypes.any,
    timezone: PropTypes.any,
    username: PropTypes.any,
    firstName: PropTypes.any,
    lastName: PropTypes.any,
    isActive: PropTypes.any,
    email: PropTypes.any,
    dateJoined: PropTypes.any,
    permissions: PropTypes.any,
  }),
};

const mapStateToProps = createStructuredSelector({
  alertTag: makeSelectAlertTag(),
  filters: makeSelectGlobalFilters(),
  historyFilters: makeSelectHistoryFilters(),
});

const mapDispatchToProps = {
  clearFilters,
  addFilter,
  setTag,
  enableOnly,
  loadFilterSets,
};

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default compose(withConnect, withPermissions)(HuntFilter);
