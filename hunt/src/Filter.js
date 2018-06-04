import React from 'react';
import { Filter, FormControl, Toolbar, Button, Icon, DropdownButton, MenuItem } from 'patternfly-react';
import { HuntSort } from './Sort.js';

export class HuntFilter extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      filterFields: this.props.filterFields,
      currentFilterType: this.props.filterFields[0],
      currentValue: ''
    };
  }

  filterAdded = (field, value) => {
    let filterText = '';
    if (field.title) {
      filterText = field.title;
    } else {
      filterText = field;
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

    let activeFilters = [...this.props.ActiveFilters, { label: filterText, id: field.id, value: value }];
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

    if (keyEvent.key === 'Enter' && currentValue && currentValue.length > 0) {
      this.setState({ currentValue: '' });
      this.filterAdded(currentFilterType, currentValue);
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
    this.setState({ activeFilters: [] });
    this.props.UpdateFilter([]);
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
    } else {
      return (
        <FormControl
          type={currentFilterType.filterType}
          value={currentValue}
          placeholder={currentFilterType.placeholder}
          onChange={e => this.updateCurrentValue(e)}
          onKeyPress={e => this.onValueKeyPress(e)}
        />
      );
    }
  }

  render() {
    const { currentFilterType } = this.state;
    const activeFilters = this.props.ActiveFilters;
    return (
	   <Toolbar>
        <div style={{ width: 450 }}>
          <Filter>
            <Filter.TypeSelector
              filterTypes={this.props.filterFields}
              currentFilterType={currentFilterType}
              onFilterTypeSelected={this.selectFilterType}
            />
            {this.renderInput()}
          </Filter>
	      <HuntSort config={this.props.sort_config} ActiveSort={this.props.ActiveSort} UpdateSort={this.props.UpdateSort}/>
	      </div>

            <Toolbar.RightContent>
		 <div className="form-group">
	         <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions">
		 <MenuItem eventKey="1">Suppress</MenuItem>
		 <MenuItem eventKey="2">Threshold</MenuItem>
		 <MenuItem divider />
		 <MenuItem eventKey="3">Tag</MenuItem>
	         </DropdownButton>
		 </div>
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
                      {item.label}
                    </Filter.Item>
                  );
                })}
              </Filter.List>
              <a
                onClick={e => {
                  e.preventDefault();
                  this.clearFilters();
                }}
              >
                Clear All Filters
              </a>

            </Toolbar.Results>
          )}
      </Toolbar>
    );
  }
}
