import React from 'react';
import { Filter, FormControl, Toolbar } from 'patternfly-react';
import { RuleSort } from './Sort.js';

export const RuleFilterFields = [
  {
    id: 'msg',
    title: 'Message',
    placeholder: 'Filter by Message',
    filterType: 'text'
  },
  {
    id: 'search',
    title: 'Content',
    placeholder: 'Filter by Content',
    filterType: 'text'
  }
];

export class RuleFilter extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      currentFilterType: RuleFilterFields[0],
      activeFilters: this.props.ActiveFilters,
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

    let activeFilters = [...this.state.activeFilters, { label: filterText, id: field.id, value: value }];
    this.setState({ activeFilters: activeFilters });
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
    const { activeFilters } = this.state;

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
    const { currentFilterType, activeFilters } = this.state;

    return (
      <div>
        <div style={{ width: 450 }}>
          <Filter>
            <Filter.TypeSelector
              filterTypes={RuleFilterFields}
              currentFilterType={currentFilterType}
              onFilterTypeSelected={this.selectFilterType}
            />
            {this.renderInput()}
          </Filter>
	      <RuleSort UpdateSort={this.props.UpdateSort}/>
        </div>
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
      </div>
    );
  }
}
