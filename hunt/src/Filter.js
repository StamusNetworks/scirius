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
import { Filter, FormControl, FormGroup, Toolbar, Button, Icon, Switch} from 'patternfly-react';
import { Shortcuts } from 'react-shortcuts';
import { HuntSort } from './Sort.js';

export class HuntFilter extends React.Component {
  constructor(props) {
    super(props);
    var tag_filters = {untagged: true, informational: true, relevant: true};
    const activeFilters = this.props.ActiveFilters; 
    for (var i = 0; i < activeFilters.length; i++) {
           if (activeFilters[i].id === 'alert.tag') {
           	tag_filters = activeFilters[i].value;
           	break;
           }
    }
    var got_alert_tag = true;
    this.state = {
      filterFields: this.props.filterFields,
      currentFilterType: this.props.filterFields[0],
      currentValue: '',
      tag_filters: tag_filters,
      got_alert_tag: got_alert_tag
    };
    this.toggleInformational = this.toggleInformational.bind(this);
    this.toggleRelevant = this.toggleRelevant.bind(this);
    this.toggleUntagged = this.toggleUntagged.bind(this);
    this.toggleSwitch = this.toggleSwitch.bind(this);
    this.updateAlertTag = this.updateAlertTag.bind(this);
  }

  updateAlertTag(tfilters) {
	this.setState({tag_filters: tfilters});
	/* Update the filters on alert.tag and send the update */
        var activeFilters = this.props.ActiveFilters; 
	var tag_filters = {id: "alert.tag", value: tfilters};
	if (activeFilters.length === 0) {
		activeFilters.push(tag_filters);
	} else {
	   var updated = false;
           for (var i = 0; i < activeFilters.length; i++) {
		if (activeFilters[i].id === 'alert.tag') {
			activeFilters[i] = tag_filters;
			updated = true;
			break;
		}
	   }
	   if (updated === false) {
		activeFilters.push(tag_filters);
	   }
	}
        this.props.UpdateFilter(activeFilters);
  }

  toggleSwitch(key) {
        var tfilters = Object.assign({}, this.state.tag_filters);
	tfilters[key] = ! this.state.tag_filters[key];
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

  componentDidUpdate(prevProps, prevState, snapshot) {
	  var i = 0;

      const activeFilters = this.props.ActiveFilters; 
      for (i = 0; i < activeFilters.length; i++) {
      if (activeFilters[i].id === 'alert.tag') {
			if (activeFilters[i].value !== this.state.tag_filters) {
				this.setState({tag_filters: activeFilters[i].value});
			}
			break;
		}
	  }
	  
      if (prevProps.filterFields !== this.props.filterFields && this.state.currentFilterType === undefined) {
        this.setState({currentFilterType: this.props.filterFields[0]})
      }
  }

  filterAdded = (field, value) => {
    let filterText = '';
    if (field.title && field.queryType !== 'filter') {
      filterText = field.title;
    } else {
      filterText = field.id;
    }
    filterText += ': ';

    if (value.filterCategory) {
      filterText +=
        (value.filterCategory.title || value.filterCategory) +
        '-' +
        (value.filterValue.title || value.filterValue);
    } else if (value.title) {
      filterText += value.title;
    } else {
      filterText += value;
    }

    var fvalue;
    if (typeof(value) === "object") {
	    if (field.id !== "alert.tag") {
	    	fvalue = value.id;
	    } else {
		fvalue = value;
	    }
    } else {
	    fvalue = value;
    }
    let activeFilters = [...this.props.ActiveFilters, { label: filterText, id: field.id, value: fvalue, negated: false, query: field.queryType }];
    this.props.UpdateFilter(activeFilters);
  };

  selectFilterType = filterType => {
    const { currentFilterType } = this.state;
    if (currentFilterType !== filterType) {
      this.setState(prevState => {
        return {
          currentValue: '',
          currentFilterType: filterType,
          filterCategory:
            filterType.filterType === 'complex-select'
              ? undefined
              : prevState.filterCategory,
          categoryValue:
            filterType.filterType === 'complex-select'
              ? ''
              : prevState.categoryValue
        };
      });
    }
  }

  filterValueSelected = filterValue => {
    const { currentFilterType, currentValue } = this.state;

    if (filterValue !== currentValue) {
      this.setState({ currentValue: filterValue });
      if (filterValue) {
        this.filterAdded(currentFilterType, filterValue);
      }
    }
  }

  filterCategorySelected = category => {
    const { filterCategory } = this.state;
    if (filterCategory !== category) {
      this.setState({ filterCategory: category, currentValue: '' });
    }
  }

  categoryValueSelected = value => {
    const { currentValue, currentFilterType, filterCategory } = this.state;

    if (filterCategory && currentValue !== value) {
      this.setState({ currentValue: value });
      if (value) {
        let filterValue = {
          filterCategory: filterCategory,
          filterValue: value
        };
        this.filterAdded(currentFilterType, filterValue);
      }
    }
  }

  updateCurrentValue = event => {
    this.setState({ currentValue: event.target.value });
  }

  onValueKeyPress = keyEvent => {
    const { currentValue, currentFilterType } = this.state;

    if (keyEvent.key === 'Enter') {
      if (currentValue && currentValue.length > 0) {
        if (currentFilterType.valueType === 'positiveint') {
          var val = parseInt(currentValue, 10);
          if (val >= 0)  {
            this.setState({ currentValue: '' });
            this.filterAdded(currentFilterType, val);
          } else {
            // Propagate event to trigger validation error
            return
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

  removeFilter = filter => {
    const activeFilters = this.props.ActiveFilters;

    let index = activeFilters.indexOf(filter);
    if (index > -1) {
      let updated = [
        ...activeFilters.slice(0, index),
        ...activeFilters.slice(index + 1)
      ];
      this.setState({ activeFilters: updated });
      this.props.UpdateFilter(updated);
    }
  }

  clearFilters = () => {
   var tag_filters = [];
   const activeFilters = this.props.ActiveFilters;
   for (var i = 0; i < activeFilters.length; i++) {
	if (activeFilters[i].id === 'alert.tag') {
		tag_filters = [ activeFilters[i], ];
		break;
	}
   }
    this.setState({ activeFilters: tag_filters });
    this.props.UpdateFilter(tag_filters);
  }

  getValidationState = () => {
    const { currentFilterType, currentValue } = this.state;
    if (currentFilterType.valueType === 'positiveint') {
	var val = parseInt(currentValue, 10);
	if (val >= 0)  {
		return 'success';
	} else {
		return 'error';
	}
    }
    return null;
  }

   _handleShortcuts = (action, event) => {
    switch (action) {
      case 'SEE_UNTAGGED':
        var tfilters = {untagged: true, informational: false, relevant: false};
        this.updateAlertTag(tfilters);
        break
      case 'SEE_INFORMATIONAL':
        tfilters = {untagged: false, informational: true, relevant: false};
        this.updateAlertTag(tfilters);
        break
      case 'SEE_RELEVANT':
        tfilters = {untagged: false, informational: false, relevant: true};
        this.updateAlertTag(tfilters);
        break
      case 'SEE_ALL':
        tfilters = {untagged: true, informational: true, relevant: true};
        this.updateAlertTag(tfilters);
        break
      default:
        break;
    }
  }

  renderInput() {
    const { currentFilterType, currentValue, filterCategory } = this.state;
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
      return (
        <Filter.CategorySelector
          filterCategories={currentFilterType.filterCategories}
          currentCategory={filterCategory}
          placeholder={currentFilterType.placeholder}
          onFilterCategorySelected={this.filterCategorySelected}
        >
          <Filter.CategoryValueSelector
            categoryValues={filterCategory && filterCategory.filterValues}
            currentValue={currentValue}
            placeholder={currentFilterType.filterCategoriesPlaceholder}
            onCategoryValueSelected={this.categoryValueSelected}
          />
        </Filter.CategorySelector>
      );
    } else if (currentFilterType.valueType === 'positiveint' ) {
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
          onChange={e => this.updateCurrentValue(e)}
          onKeyPress={e => this.onValueKeyPress(e)}
        />
        </FormGroup>
      );
    } else {
      return (
      	<FormGroup
	  controlId="input-filter"
	  validationState={this.getValidationState()}
      	>
        <FormControl
          type={currentFilterType.filterType}
          value={currentValue}
          placeholder={currentFilterType.placeholder}
          onChange={e => this.updateCurrentValue(e)}
          onKeyPress={e => this.onValueKeyPress(e)}
        />
	</FormGroup>
      );
    }
  }

  render() {
    const { currentFilterType } = this.state;
    var activeFilters = []
    this.props.ActiveFilters.forEach( item => {
	if (item.query === undefined) {
		/* remove alert.tag from display as it is handle by switches*/
		if (item.id !== 'alert.tag') {
			activeFilters.push(item);
		}
	} else if (this.props.queryType.indexOf(item.query) !== -1) {
		activeFilters.push(item);
	}
    });
    var menuFilters = [];
    this.props.filterFields.forEach( item => {
	    if (item.filterType !== 'hunt') {
		menuFilters.push(item);
	    }
    });
    
    return (
          <Shortcuts
        name='HUNT_FILTER'
        handler={this._handleShortcuts}
        isolate={true}
        targetNodeSelector='body'
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
	      {this.props.sort_config &&
	      <HuntSort config={this.props.sort_config} ActiveSort={this.props.ActiveSort} UpdateSort={this.props.UpdateSort}/>
	      }
	      { this.state.got_alert_tag &&
        <div className="form-group">
          <ul className="list-inline">
            <li><Switch bsSize="small" onColor="info" value={this.state.tag_filters.informational} onChange={this.toggleInformational}/> Informational</li>
            <li><Switch bsSize="small" onColor="warning" value={this.state.tag_filters.relevant} onChange={this.toggleRelevant}/> Relevant</li>
            <li><Switch bsSize="small" onColor="primary" value={this.state.tag_filters.untagged} onChange={this.toggleUntagged}/> Untagged</li>
          </ul>
        </div>
	      }
	      </div>

            <Toolbar.RightContent>
	    { this.props.actionsButtons && this.props.actionsButtons() }
	    {this.props.displayToggle &&
                        <Toolbar.ViewSelector>
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
          </Toolbar.ViewSelector>
	    }
            </Toolbar.RightContent>

        {activeFilters &&
          activeFilters.length > 0 && (
            <Toolbar.Results>
              <Filter.ActiveLabel>{'Active Filters:'}</Filter.ActiveLabel>
              <Filter.List>
                {activeFilters.map((item, index) => {
                  return (
                    <Filter.Item
                      key={index}
                      onRemove={this.removeFilter}
                      filterData={item}
                    >
		      { item.negated &&
		         <span>Not</span>
		      } {item.label}
                    </Filter.Item>
                  );
                })}
              </Filter.List>
              <a
                onClick={e => {
                  e.preventDefault();
                  this.clearFilters();
                }}
                style={{cursor:'pointer'}}
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
