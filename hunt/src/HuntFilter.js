/* eslint-disable react/sort-comp,no-else-return */
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
import { Filter, FormControl, FormGroup, Toolbar, Button, Icon, Switch } from 'patternfly-react';
import { Shortcuts } from 'react-shortcuts';
import Select from 'react-select';
import { HuntSort } from './Sort';

// https://www.regextester.com/104038
const IP_REGEXP = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;

export class HuntFilter extends React.Component {
    constructor(props) {
        super(props);
        let tagFilters = { untagged: true, informational: true, relevant: true };
        const activeFilters = this.props.ActiveFilters;
        for (let i = 0; i < activeFilters.length; i += 1) {
            if (activeFilters[i].id === 'alert.tag') {
                tagFilters = activeFilters[i].value;
                break;
            }
        }
        let gotAlertTag = true;
        if (this.props.got_alert_tag === false) {
            gotAlertTag = false;
        }
        this.state = {
            // eslint-disable-next-line react/no-unused-state
            filterFields: this.props.filterFields,
            currentFilterType: this.props.filterFields[0],
            currentValue: '',
            tagFilters,
            gotAlertTag
        };
        this.toggleInformational = this.toggleInformational.bind(this);
        this.toggleRelevant = this.toggleRelevant.bind(this);
        this.toggleUntagged = this.toggleUntagged.bind(this);
        this.toggleSwitch = this.toggleSwitch.bind(this);
        this.updateAlertTag = this.updateAlertTag.bind(this);
    }

    componentDidUpdate(prevProps) {
        let i = 0;

        const activeFilters = this.props.ActiveFilters;
        for (i = 0; i < activeFilters.length; i += 1) {
            if (activeFilters[i].id === 'alert.tag') {
                if (activeFilters[i].value !== this.state.tagFilters) {
                    // eslint-disable-next-line react/no-did-update-set-state
                    this.setState({ tagFilters: activeFilters[i].value });
                }
                break;
            }
        }

        if (prevProps.filterFields !== this.props.filterFields && this.state.currentFilterType === undefined) {
            // eslint-disable-next-line react/no-did-update-set-state
            this.setState({ currentFilterType: this.props.filterFields[0] });
        }
    }

    onValueKeyPress = (keyEvent) => {
        const { currentValue, currentFilterType } = this.state;

        if (keyEvent.key === 'Enter') {
            if (currentValue && currentValue.length > 0) {
                if (currentFilterType.valueType === 'positiveint') {
                    const val = parseInt(currentValue, 10);
                    if (val >= 0) {
                        this.setState({ currentValue: '' });
                        this.filterAdded(currentFilterType, val);
                    } else {
                        // Propagate event to trigger validation error
                        return;
                    }
                } else if (currentFilterType.valueType === 'ip') {
                    if (IP_REGEXP.test(currentValue)) {
                        this.setState({ currentValue: '' });
                        this.filterAdded(currentFilterType, currentValue);
                    }
                } else {
                    this.setState({ currentValue: '' });
                    this.filterAdded(currentFilterType, currentValue);
                }
            }
            keyEvent.stopPropagation();
            keyEvent.preventDefault();
        }
    }

    getValidationState = () => {
        const { currentFilterType, currentValue } = this.state;
        if (currentFilterType.valueType === 'positiveint') {
            const val = parseInt(currentValue, 10);
            if (val >= 0) {
                return 'success';
            }
            return 'error';
        }
        return null;
    }

    updateAlertTag(tfilters) {
        this.setState({ tagFilters: tfilters });
        /* Make a copy of the ActiveFilters instead of mutating it. Update the filters on alert.tag and send the update */
        const activeFilters = JSON.parse(JSON.stringify(this.props.ActiveFilters))
        const tagFilters = { id: 'alert.tag', value: tfilters };
        if (activeFilters.length === 0) {
            activeFilters.push(tagFilters);
        } else {
            let updated = false;
            for (let i = 0; i < activeFilters.length; i += 1) {
                if (activeFilters[i].id === 'alert.tag') {
                    activeFilters[i] = tagFilters;
                    updated = true;
                    break;
                }
            }
            if (updated === false) {
                activeFilters.push(tagFilters);
            }
        }
        this.props.UpdateFilter(activeFilters);
    }

    toggleSwitch(key) {
        const tfilters = Object.assign({}, this.state.tagFilters);
        tfilters[key] = !this.state.tagFilters[key];
        this.updateAlertTag(tfilters);
    }

    toggleInformational() {
        this.toggleSwitch('informational');
    }

    toggleUntagged() {
        this.toggleSwitch('untagged');
    }

    toggleRelevant() {
        this.toggleSwitch('relevant');
    }

    filterAdded = (field, value) => {
        let filterText = '';
        let fieldId = field.id;

        if (field.filterType !== 'complex-select-text') {
            if (field.filterType === 'select' || field.filterType === 'complex-select') {
                filterText = field.id;
                fieldId = filterText;
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
        } else {
            filterText += value;
        }

        let fvalue;
        if (typeof (value) === 'object') {
            if (field.id !== 'alert.tag') {
                fvalue = value.id;
            } else {
                fvalue = value;
            }
        } else {
            fvalue = value;
        }
        const activeFilters = [...this.props.ActiveFilters, {
            label: filterText, id: fieldId, value: fvalue, negated: false, query: field.queryType
        }];
        this.props.UpdateFilter(activeFilters);
    };

    selectFilterType = (filterType) => {
        const { currentFilterType } = this.state;
        if (currentFilterType !== filterType) {
            this.setState((prevState) => ({
                currentValue: '',
                currentFilterType: filterType,
                filterCategory:
                    filterType.filterType === 'complex-select' ? undefined : prevState.filterCategory,
                categoryValue:
                    filterType.filterType === 'complex-select' ? '' : prevState.categoryValue
            }));
        }
    }

    filterValueSelected = (filterValue) => {
        // used by Select component
        if (filterValue.id) {
            filterValue = filterValue.id;
        }

        const { currentFilterType, currentValue } = this.state;

        if (filterValue !== currentValue) {
            this.setState({ currentValue: filterValue });
            if (filterValue) {
                this.filterAdded(currentFilterType, filterValue);
            }
        }
    }

    filterCategorySelected = (category) => {
        const { filterCategory } = this.state;
        if (filterCategory !== category) {
            this.setState({ filterCategory: category, filterSubCategory: undefined, currentValue: '' });
        }
    }

    filterSubCategorySelected = (category) => {
        const { filterSubCategory } = this.state;
        if (filterSubCategory !== category) {
            this.setState({ filterSubCategory: category, currentValue: '' });
        }
    }

    categoryValueSelected = (value) => {
        const { currentValue, currentFilterType, filterCategory } = this.state;

        if (filterCategory && currentValue !== value) {
            this.setState({ currentValue: value });
            if (value) {
                const filterValue = {
                    filterCategory,
                    filterValue: value
                };
                this.filterAdded(currentFilterType, filterValue);
            }
        }
    }

    updateCurrentValue = (event) => {
        const { currentFilterType } = this.state;
        let error = false;
        if (currentFilterType.valueType === 'ip') {
            const numbers = event.target.value.split(/\.|:/);
            const filteredNum = numbers.filter((item) => item !== '');

            const UINT_REGEXP_V4 = /^\d*[0-9]\d*$/;
            const UINT_REGEXP_V6 = /[0-9a-fA-F]{1,4}/;
            for (let idx = 0; idx < filteredNum.length; idx += 1) {
                if (!UINT_REGEXP_V4.test(filteredNum[idx]) && !UINT_REGEXP_V6.test(filteredNum[idx])) {
                    error = true;
                    break;
                }
            }
        }
        if (!error) this.setState({ currentValue: event.target ? event.target.value : event /* used by Select component */ });
    }

    removeFilter = (filter) => {
        const activeFilters = this.props.ActiveFilters;

        const index = activeFilters.indexOf(filter);
        if (index > -1) {
            const updated = [
                ...activeFilters.slice(0, index),
                ...activeFilters.slice(index + 1)
            ];
            // eslint-disable-next-line react/no-unused-state
            this.setState({ activeFilters: updated });
            this.props.UpdateFilter(updated);
        }
    }

    clearFilters = () => {
        let tagFilters = [];
        const activeFilters = this.props.ActiveFilters;
        for (let i = 0; i < activeFilters.length; i += 1) {
            if (activeFilters[i].id === 'alert.tag') {
                tagFilters = [activeFilters[i]];
                break;
            }
        }
        // eslint-disable-next-line react/no-unused-state
        this.setState({ activeFilters: tagFilters });
        this.props.UpdateFilter(tagFilters);
    }

    getValidationState = () => {
        const { currentFilterType, currentValue } = this.state;
        if (currentFilterType.valueType === 'positiveint') {
            const val = parseInt(currentValue, 10);
            if (val >= 0) {
                return 'success';
            } else {
                return 'error';
            }
        } else if (currentFilterType.valueType === 'ip') {
            if (!IP_REGEXP.test(currentValue)) {
                return 'error';
            }
            return 'success';
        }
        return null;
    }

    handleShortcuts = (action) => {
        switch (action) {
            case 'SEE_UNTAGGED': {
                const tfilters = { untagged: true, informational: false, relevant: false };
                this.updateAlertTag(tfilters);
                break;
            }
            case 'SEE_INFORMATIONAL': {
                const tfilters = { untagged: false, informational: true, relevant: false };
                this.updateAlertTag(tfilters);
                break;
            }
            case 'SEE_RELEVANT': {
                const tfilters = { untagged: false, informational: false, relevant: true };
                this.updateAlertTag(tfilters);
                break;
            }
            case 'SEE_ALL': {
                const tfilters = { untagged: true, informational: true, relevant: true };
                this.updateAlertTag(tfilters);
                break;
            }
            default:
                break;
        }
    }

    renderInput() {
        const {
            currentFilterType, currentValue, filterCategory, filterSubCategory
        } = this.state;
        if (!currentFilterType) {
            return null;
        }

        if (currentFilterType.filterType === 'select') {
            return (
                <Filter.ValueSelector
                    filterValues={currentFilterType.filterValues}
                    placeholder={currentFilterType.placeholder}
                    currentValue={currentValue}
                    onFilterValueSelected={this.filterValueSelected}
                />
            );
        } else if (currentFilterType.filterType === 'complex-select') {
            const customStyles = {
                option: (provided, state) => ({
                    ...provided,
                    color: state.isSelected ? null : 'black',
                    backgroundColor: state.isFocused ? '#dcc6c5' : null,
                    ':active': {
                        backgroundColor: state.isSelected ? null : '#7b1244',
                        color: state.isSelected ? null : 'white'
                    }
                }),
                container: (provided) => ({
                    ...provided,
                    display: 'inline-block',
                    width: '250px',
                    minHeight: '1px',
                    textAlign: 'left',
                    border: 'none',
                }),
                control: (provided, state) => ({
                    ...provided,
                    border: state.isFocused ? '1px solid #9c9c9c' : '1px solid #bbb',
                    boxShadow: state.isFocused ? null : null,
                    '&:hover': {
                        border: state.isFocused ? '1px solid #9c9c9c' : '1px solid #bbb',
                        backgroundColor: '#e8e8e8',
                        color: 'yellow'
                    },
                    borderRadius: '0',
                    minHeight: '1px',
                    height: '26px',
                    cursor: 'pointer'
                }),
                input: (provided) => ({
                    ...provided,
                    minHeight: '1px',
                }),
                dropdownIndicator: (provided) => ({
                    ...provided,
                    minHeight: '1px',
                    paddingTop: '0',
                    paddingBottom: '5',
                    color: '#8b8d8f',
                }),
                indicatorSeparator: (provided) => ({
                    ...provided,
                    minHeight: '1px',
                    height: '12px',
                }),
                valueContainer: (provided) => ({
                    ...provided,
                    minHeight: '1px',
                    height: '25px',
                    paddingTop: '0',
                    paddingBottom: '0',
                    position: 'static !important',
                    fontWeight: 600
                }),
                singleValue: (provided) => ({
                    ...provided,
                    minHeight: '1px',
                    paddingBottom: '2px',
                }),
            };

            if (currentFilterType.filterCategories) {
                return (
                    <Filter.CategorySelector
                        filterCategories={currentFilterType.filterCategories}
                        currentCategory={filterCategory}
                        placeholder={currentFilterType.placeholder}
                        onFilterCategorySelected={this.filterCategorySelected}
                    >
                        {filterCategory && <Select
                            styles={customStyles}
                            value={currentValue}
                            options={filterCategory && filterCategory.filterValues}
                            onChange={this.filterValueSelected}
                            className="basic-single toolbar-pf-filter"
                            classNamePrefix="select"
                            placeholder={'Choose an Organization'}
                        />}
                    </Filter.CategorySelector>
                );
            } else {
                return (
                    <Select
                        styles={customStyles}
                        value={currentValue}
                        options={currentFilterType && currentFilterType.filterValues}
                        onChange={this.filterValueSelected}
                        className="basic-single toolbar-pf-filter"
                        classNamePrefix="select"
                        placeholder={'Choose an Organization'}
                    />
                );
            }
        } else if (currentFilterType.filterType === 'complex-select-text') {
            return (
                <Filter.CategorySelector
                    filterCategories={currentFilterType.filterCategories}
                    currentCategory={filterCategory}
                    placeholder={currentFilterType.placeholder}
                    onFilterCategorySelected={this.filterCategorySelected}
                >
                    {filterCategory && filterCategory.valueType === undefined && <Filter.CategorySelector
                        filterCategories={filterCategory && filterCategory.filterValues}
                        currentCategory={filterSubCategory}
                        placeholder={currentFilterType.filterCategoriesPlaceholder}
                        onFilterCategorySelected={this.filterSubCategorySelected}
                    />}
                    {filterCategory && filterSubCategory && <FormGroup
                        controlId="input-filter"
                        validationState={this.getValidationState()}
                    >
                        <FormControl
                            type={currentFilterType.filterType}
                            value={currentValue}
                            placeholder={filterSubCategory.placeholder}
                            onChange={(e) => this.updateCurrentValue(e)}
                            onKeyPress={(e) => this.onValueKeyPress(e)}
                        />
                    </FormGroup>}
                    {filterCategory && filterCategory.valueType && <FormGroup
                        controlId="input-filter"
                        validationState={this.getValidationState()}
                    >
                        <FormControl
                            type={currentFilterType.filterType}
                            value={currentValue}
                            placeholder={filterCategory.placeholder}
                            onChange={(e) => this.updateCurrentValue(e)}
                            onKeyPress={(e) => this.onValueKeyPress(e)}
                        />
                    </FormGroup>}
                </Filter.CategorySelector>
            );
        } else if (currentFilterType.valueType === 'positiveint') {
            return (
                <FormGroup
                    controlId="input-filter"
                    validationState={this.getValidationState()}
                >
                    <FormControl
                        type={currentFilterType.filterType}
                        value={currentValue}
                        min={0}
                        placeholder={currentFilterType.placeholder}
                        onChange={(e) => this.updateCurrentValue(e)}
                        onKeyPress={(e) => this.onValueKeyPress(e)}
                    />
                </FormGroup>
            );
        }
        return (
            <FormGroup
                controlId="input-filter"
                validationState={this.getValidationState()}
            >
                <FormControl
                    type={currentFilterType.filterType}
                    value={currentValue}
                    placeholder={currentFilterType.placeholder}
                    onChange={(e) => this.updateCurrentValue(e)}
                    onKeyPress={(e) => this.onValueKeyPress(e)}
                />
            </FormGroup>
        );
    }

    render() {
        const { currentFilterType } = this.state;
        const activeFilters = [];
        this.props.ActiveFilters.forEach((item) => {
            if (item.query === undefined) {
                /* remove alert.tag from display as it is handle by switches */
                if (item.id !== 'alert.tag') {
                    activeFilters.push(item);
                }
            } else if (this.props.queryType.indexOf(item.query) !== -1) {
                activeFilters.push(item);
            }
        });
        const menuFilters = [];
        this.props.filterFields.forEach((item) => {
            if (item.filterType !== 'hunt') {
                menuFilters.push(item);
            }
        });

        return (
            <Shortcuts
                name="HUNT_FILTER"
                handler={this.handleShortcuts}
                isolate
                targetNodeSelector="body"
            >
                <Toolbar>
                    <div>
                        <Filter>
                            <Filter.TypeSelector
                                filterTypes={menuFilters}
                                currentFilterType={currentFilterType}
                                onFilterTypeSelected={this.selectFilterType}
                            />
                            {this.renderInput()}
                        </Filter>
                        {this.props.sort_config && <HuntSort config={this.props.sort_config}
                            ActiveSort={this.props.ActiveSort}
                            UpdateSort={this.props.UpdateSort}
                            disabled={this.props.disable_sort ? this.props.disable_sort : false}
                        />}
                        {this.state.gotAlertTag && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && <div className="form-group">
                            <ul className="list-inline">
                                <li><Switch bsSize="small"
                                    onColor="info"
                                    value={this.state.tagFilters.informational}
                                    onChange={this.toggleInformational}
                                /> Informational
                                </li>
                                <li><Switch bsSize="small"
                                    onColor="warning"
                                    value={this.state.tagFilters.relevant}
                                    onChange={this.toggleRelevant}
                                /> Relevant
                                </li>
                                <li><Switch bsSize="small"
                                    onColor="primary"
                                    value={this.state.tagFilters.untagged}
                                    onChange={this.toggleUntagged}
                                /> Untagged
                                </li>
                            </ul>
                        </div>}
                    </div>

                    <Toolbar.RightContent>
                        {this.props.actionsButtons && this.props.actionsButtons()}
                        {this.props.displayToggle && <Toolbar.ViewSelector>
                            <Button
                                title="List View"
                                bsStyle="link"
                                className={{ active: this.props.config.view_type === 'list' }}
                                onClick={() => {
                                    this.props.setViewType('list');
                                }}
                            >
                                <Icon type="fa" name="th-list" />
                            </Button>
                            <Button
                                title="Card View"
                                bsStyle="link"
                                className={{ active: this.props.config.view_type === 'card' }}
                                onClick={() => {
                                    this.props.setViewType('card');
                                }}
                            >
                                <Icon type="fa" name="th" />
                            </Button>
                        </Toolbar.ViewSelector>}
                    </Toolbar.RightContent>

                    {activeFilters && activeFilters.length > 0 && (
                        <Toolbar.Results>
                            <Filter.ActiveLabel>{'Active Filters:'}</Filter.ActiveLabel>
                            <Filter.List>
                                {activeFilters.map((item, index) => (
                                    <Filter.Item
                                        // eslint-disable-next-line react/no-array-index-key
                                        key={index}
                                        onRemove={this.removeFilter}
                                        filterData={item}
                                    >
                                        {item.negated && <span className="badge badge-primary">Not</span>}
                                        {item.label}
                                    </Filter.Item>
                                ))}
                            </Filter.List>
                            <a
                                role="button"
                                onClick={(e) => {
                                    e.preventDefault();
                                    this.clearFilters();
                                }}
                                style={{ cursor: 'pointer' }}
                            >
                                Clear All Filters
                            </a>

                        </Toolbar.Results>
                    )}
                </Toolbar>
            </Shortcuts>
        );
    }
}
HuntFilter.propTypes = {
    filterFields: PropTypes.any,
    ActiveFilters: PropTypes.any,
    got_alert_tag: PropTypes.any,
    setViewType: PropTypes.any,
    queryType: PropTypes.any,
    sort_config: PropTypes.any,
    disable_sort: PropTypes.any,
    ActiveSort: PropTypes.any,
    UpdateSort: PropTypes.any,
    config: PropTypes.any,
    actionsButtons: PropTypes.any,
    displayToggle: PropTypes.any,
    UpdateFilter: PropTypes.any,
};
