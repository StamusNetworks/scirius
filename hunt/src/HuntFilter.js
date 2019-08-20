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
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { Filter, FormControl, FormGroup, Toolbar, Button, Icon, Switch } from 'patternfly-react';
import { Shortcuts } from 'react-shortcuts';
import Select from 'react-select';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import VerticalNavItems from 'hunt_common/components/VerticalNavItems';
import { HuntSort } from './Sort';
import FilterList from './components/FilterList/index';
import FilterSetSave from './components/FilterSetSaveModal';
import { makeSelectAlertTag, sections, addFilter, clearFilters, setTag, enableOnly } from './containers/App/stores/global';
import { loadFilterSets } from './components/FilterSets/store';

// https://www.regextester.com/104038
const IP_REGEXP = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;

class HuntFilter extends React.Component {
    constructor(props) {
        super(props);
        let gotAlertTag = true;
        if (this.props.got_alert_tag === false) {
            gotAlertTag = false;
        }
        this.state = {
            // eslint-disable-next-line react/no-unused-state
            filterFields: this.props.filterFields,
            currentFilterType: this.props.filterFields[0],
            currentValue: '',
            gotAlertTag,
            filterSets: { showModal: false, shared: false, description: '' },
            filterSetName: '',
            errors: undefined,
            user: undefined
        };
        this.loadHuntFilterSetsModal = this.loadHuntFilterSetsModal.bind(this);
        this.setSharedFilter = this.setSharedFilter.bind(this);
        this.closeHuntFilterSetsModal = this.closeHuntFilterSetsModal.bind(this);
        this.submitFilterSets = this.submitFilterSets.bind(this);
        this.handleFieldChange = this.handleFieldChange.bind(this);
        this.handleDescriptionChange = this.handleDescriptionChange.bind(this);
    }

    componentDidMount() {
        axios.get(`${config.API_URL}${config.USER_PATH}current_user/`)
        .then((currentUser) => {
            this.setState({ user: currentUser.data });
        });
    }

    componentDidUpdate(prevProps) {
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
                        this.filterAdded(currentFilterType, val, true);
                    } else {
                        // Propagate event to trigger validation error
                        return;
                    }
                } else if (currentFilterType.valueType === 'ip') {
                    if (IP_REGEXP.test(currentValue)) {
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
    }

    filterAdded = (field, value, fullString) => {
        let filterText = '';
        let fieldId = field.id;
        if (['msg', 'not_in_msg', 'search'].indexOf(field.id) !== -1) {
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
        if (typeof (value) === 'object') {
            if (field.id !== 'alert.tag') {
                fvalue = value.id;
            } else {
                fvalue = value;
            }
        } else {
            fvalue = value;
        }
        this.props.addFilter(
            this.props.filterType,
            {
                label: filterText,
                id: fieldId,
                value: fvalue,
                negated: false,
                query: field.queryType,
                fullString
            }
        );
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

    selectFilterValue = (filterValue) => {
        const { currentFilterType, currentValue } = this.state;

        if (filterValue !== currentValue) {
            this.setState({ currentValue: filterValue });
            if (filterValue) {
                this.filterAdded(currentFilterType, filterValue, true);
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
                this.filterAdded(currentFilterType, filterValue, true);
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
        } else if (['msg', 'not_in_msg', 'search'].indexOf(this.state.currentFilterType.id) === -1 && event.target.value.indexOf(' ') !== -1) {
            // No space allowed to avoid breaking ES queries
            error = true;
        }
        if (!error) this.setState({ currentValue: event.target ? event.target.value : event /* used by Select component */ });
    }

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
                this.props.enableOnly('untagged');
                break;
            }
            case 'SEE_INFORMATIONAL': {
                this.props.enableOnly('informational');
                break;
            }
            case 'SEE_RELEVANT': {
                this.props.enableOnly('relevant');
                break;
            }
            case 'SEE_ALL': {
                this.props.enableOnly('all');
                break;
            }
            default:
                break;
        }
    }

    closeHuntFilterSetsModal() {
        this.setState({ filterSets: { showModal: false, shared: false, description: '' } });
    }

    loadHuntFilterSetsModal() {
        this.setState({ filterSets: { showModal: true, shared: false } });
    }

    setSharedFilter(e) {
        this.setState({ filterSets: { showModal: true, shared: e.target.checked, description: this.state.filterSets.description } });
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
                    onFilterValueSelected={this.selectFilterValue}
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
                    zIndex: '1000'
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
                            onChange={this.selectFilterValue}
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
                        onChange={this.selectFilterValue}
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
                            type={filterSubCategory.filterType}
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

    handleFieldChange(event) {
        this.setState({ filterSetName: event.target.value, filterSets: { showModal: true, shared: this.state.filterSets.shared, description: this.state.filterSets.description } });
    }

    handleDescriptionChange(event) {
        this.setState({ filterSetName: this.state.filterSetName, filterSets: { showModal: true, shared: this.state.filterSets.shared, description: event.target.value } });
    }

    submitFilterSets() {
        const filters = this.props.ActiveFilters;
        this.setState({ errors: undefined });

        // Check and add tags if not already here
        let found = false;
        for (let idx = 0; idx < this.props.ActiveFilters.length; idx += 1) {
            if (this.props.ActiveFilters[idx].id === 'alert.tag') {
                found = true;
                break;
            }
        }
        if (!found) {
            const tags = { id: 'alert.tag', value: { untagged: true, informational: true, relevant: true } };
            filters.push(tags);
        }

        axios.post(config.API_URL + config.HUNT_FILTER_SETS, { name: this.state.filterSetName, page: this.props.page, content: filters, share: this.state.filterSets.shared, description: this.state.filterSets.description })
        .then(() => {
            this.props.loadFilterSets();
            this.closeHuntFilterSetsModal();
            this.setState({ errors: undefined });
        })
        .catch((error) => {
            let errors = error.response.data;

            if (error.response.status === 403) {
                const noRights = this.state.user.is_active && !this.state.user.is_staff && !this.state.user.is_superuser && this.state.filterSets.shared;
                if (noRights) {
                    errors = { permission: ['Insufficient permissions. "Shared" is not allowed.'] };
                }
            }
            this.setState({ errors });
        });
    }

    renderInputHuntFilterSetsModal() {
        let { page } = this.props;
        for (let idxPages = 0; idxPages < VerticalNavItems.length; idxPages += 1) {
            const item = VerticalNavItems[idxPages];

            if (item.def === page) {
                page = item.title;
                break;
            }
        }

        const noRights = this.state.user !== undefined && this.state.user.is_active && !this.state.user.is_staff && !this.state.user.is_superuser;
        return (
            <FilterSetSave
                title={'Create new Filter Set'}
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
                        {this.state.gotAlertTag && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && <div className="form-group" style={{ paddingTop: '3px', height: '25px' }}>
                            <ul className="list-inline">
                                <li><Switch bsSize="small"
                                    onColor="info"
                                    value={this.props.alertTag.value.informational}
                                    onChange={() => this.props.setTag('informational', !this.props.alertTag.value.informational)}
                                /> Informational
                                </li>
                                <li><Switch bsSize="small"
                                    onColor="warning"
                                    value={this.props.alertTag.value.relevant}
                                    onChange={() => this.props.setTag('relevant', !this.props.alertTag.value.relevant)}
                                /> Relevant
                                </li>
                                <li><Switch bsSize="small"
                                    onColor="primary"
                                    value={this.props.alertTag.value.untagged}
                                    onChange={() => this.props.setTag('untagged', !this.props.alertTag.value.untagged)}
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
                            <FilterList filters={activeFilters} filterType={this.props.filterType} />
                            <a
                                data-toggle="tooltip"
                                data-placement="top"
                                title="Clear All Filters"
                                id="clear"
                                role="button"
                                onClick={(e) => {
                                    e.preventDefault();
                                    this.props.clearFilters(this.props.filterType);
                                }}
                                style={{ cursor: 'pointer' }}
                            >
                                Clear
                            </a>
                            {this.props.page !== 'HISTORY' && <a
                                data-toggle="tooltip"
                                data-placement="top"
                                title="Save Filter Set"
                                id="saveall"
                                role="button"
                                onClick={(e) => {
                                    e.preventDefault();
                                    this.loadHuntFilterSetsModal();
                                }}
                                style={{ cursor: 'pointer' }}
                            >
                                |&nbsp;&nbsp;Save
                            </a>}
                        </Toolbar.Results>
                    )}
                </Toolbar>
                {this.renderInputHuntFilterSetsModal()}
            </Shortcuts>
        );
    }
}

HuntFilter.defaultProps = {
    filterType: sections.GLOBAL,
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
        })
    }),
    loadFilterSets: PropTypes.func,
};

const mapStateToProps = createStructuredSelector({
    alertTag: makeSelectAlertTag(),
});

const mapDispatchToProps = {
    clearFilters,
    addFilter,
    setTag,
    enableOnly,
    loadFilterSets,
};

export default connect(mapStateToProps, mapDispatchToProps)(HuntFilter);
