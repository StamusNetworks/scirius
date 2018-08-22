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
import axios from 'axios';
import * as config from './config/Api.js';
import { PaginationRow, DropdownButton, MenuItem } from 'patternfly-react';
import { PAGINATION_VIEW_TYPES } from 'patternfly-react';


export class HuntPaginationRow extends React.Component {
  constructor(props) {
    super(props);
    this.onPageInput = this.onPageInput.bind(this);
    this.onPerPageSelect = this.onPerPageSelect.bind(this);
  };

  onPageInput = e => {
    const val = parseInt(e.target.value, 10);
    if (val > 0) {
    	const newPaginationState = Object.assign({}, this.props.pagination);
    	newPaginationState.page = val;
    	this.props.onPaginationChange(newPaginationState);
    }
  }

  onPerPageSelect = (eventKey, e) => {
    const newPaginationState = Object.assign({}, this.props.pagination);
    newPaginationState.perPage = eventKey;
    this.props.onPaginationChange(newPaginationState);
  }

  render() {
    const {
      viewType,
      pageInputValue,
      amountOfPages,
      pageSizeDropUp,
      itemCount,
      itemsStart,
      itemsEnd,
      onFirstPage,
      onPreviousPage,
      onNextPage,
      onLastPage
    } = this.props;

    return (
      <PaginationRow
        viewType={viewType}
        pageInputValue={pageInputValue}
        pagination={this.props.pagination}
        amountOfPages={amountOfPages}
        pageSizeDropUp={pageSizeDropUp}
        itemCount={itemCount}
        itemsStart={itemsStart}
        itemsEnd={itemsEnd}
        onPerPageSelect={this.onPerPageSelect}
        onFirstPage={onFirstPage}
        onPreviousPage={onPreviousPage}
        onPageInput={this.onPageInput}
        onNextPage={onNextPage}
        onLastPage={onLastPage}
      />
    );
  }
}

function noop() {
	return;
}

HuntPaginationRow.propTypes = {
  viewType: PropTypes.oneOf(PAGINATION_VIEW_TYPES).isRequired,
  pageInputValue: PropTypes.number.isRequired,
  amountOfPages: PropTypes.number.isRequired,
  pageSizeDropUp: PropTypes.bool,
  itemCount: PropTypes.number.isRequired,
  itemsStart: PropTypes.number.isRequired,
  itemsEnd: PropTypes.number.isRequired,
  onFirstPage: PropTypes.func,
  onPreviousPage: PropTypes.func,
  onNextPage: PropTypes.func,
  onLastPage: PropTypes.func
};

HuntPaginationRow.defaultProps = {
  pageSizeDropUp: true,
  onFirstPage: noop,
  onPreviousPage: noop,
  onNextPage: noop,
  onLastPage: noop
};


export class HuntList extends React.Component {
    constructor(props) {
         super(props);
	 this.buildListUrlParams = this.buildListUrlParams.bind(this);
         this.fetchData = this.fetchData.bind(this);
         this.handlePaginationChange = this.handlePaginationChange.bind(this);
         this.onFirstPage = this.onFirstPage.bind(this);
         this.onNextPage = this.onNextPage.bind(this);
         this.onPrevPage = this.onPrevPage.bind(this);
         this.onLastPage = this.onLastPage.bind(this);
         this.UpdateFilter = this.UpdateFilter.bind(this);
         this.UpdateSort = this.UpdateSort.bind(this);
     
         this.buildFilter = this.buildFilter.bind(this);

         this.setViewType = this.setViewType.bind(this);

         this.actionsButtons = this.actionsButtons.bind(this);
         this.createAction = this.createAction.bind(this);
         this.closeAction = this.closeAction.bind(this);
         this.loadActions = this.loadActions.bind(this);

         this.updateAlertTag = this.updateAlertTag.bind(this);
    }

   buildFilter(filters) {
     var l_filters = {};
     for (var i=0; i < filters.length; i++) {
            if (filters[i].id in l_filters) {
               l_filters[filters[i].id] += "," + filters[i].value;
            } else {
               l_filters[filters[i].id] = filters[i].value;
            }
	 }
     var string_filters = "";
     for (var k in l_filters) {
         string_filters += "&" + k + "=" + l_filters[k];
     }

     return string_filters;
   }

  updateAlertTag(tfilters) {
	/* Update the filters on alert.tag and send the update */
    var activeFilters = Object.assign([], this.props.filters);
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
        this.UpdateFilter(activeFilters);
  }

  addFilter = (field, value, negated) => {
    if (field !== "alert.tag") {
    	let filterText = '';
    	filterText = field;
    	filterText += ': ';
    	filterText += value;
	let activeFilters = [...this.props.filters, { label: filterText, id: field, value: value, negated: negated }];
    	this.UpdateFilter(activeFilters);
    } else {
        var tfilters = {};
        if (negated) {
            tfilters = {untagged: true, informational: true, relevant: true};
	        tfilters[value] = false;
        } else {
            tfilters = {untagged: false, informational: false, relevant: false};
	        tfilters[value] = true;
        }
	    this.updateAlertTag(tfilters);
    }
  }

  handlePaginationChange(pagin) {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination = pagin;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
  }

  onFirstPage() {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination.page = 1;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
  }

  onNextPage() {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination.page = newListState.pagination.page + 1;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
  }

  onPrevPage() {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination.page = newListState.pagination.page - 1;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
  }

  onLastPage() {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination.page = Math.floor(this.state.count / this.props.config.pagination.perPage) + 1;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
  }

   UpdateFilter(filters) {
     const newListState = Object.assign({}, this.props.config);
     newListState.pagination.page = 1;
     this.props.updateFilterState(filters);
     this.props.updateListState(newListState);
     this.fetchData(newListState, filters);
     if (this.props.needReload) {
        this.props.needReload();
     }
     this.loadActions(filters)
   }

   UpdateSort(sort) {
     const newListState = Object.assign({}, this.props.config);
     newListState.sort = sort;
     this.props.updateListState(newListState);
     this.fetchData(newListState, this.props.filters);
   }

   setViewType(type) {
        const newListState = Object.assign({}, this.props.config);
        newListState.view_type = type;
        this.props.updateListState(newListState);
   }


   fetchData(state, filters) {
        return;
   }

  loadActions(filters) {
       if (filters === undefined) {
          filters = this.props.filters;
       }
       filters = filters.map(f => f['id']);
       var req_data = {fields: filters};
       axios.post(config.API_URL + config.PROCESSING_PATH + "test_actions/", req_data).then(
         res => {this.setState({supported_actions: res.data.actions});});
  }

  createAction(type) {
	this.setState({action: {view: true, type: type}});
  }

  closeAction() {
        this.setState({action: {view: false, type: null}});
  }

  actionsButtons() {
      if (this.state.supported_actions.length === 0) {
        return (
        <div className="form-group">
          <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions" disabled>
          </DropdownButton>
        </div>
        );
      }
      var actions = []
      let eventKey = 1;
      for (let i = 0; i < this.state.supported_actions.length; i++) {
          let action = this.state.supported_actions[i];
          if (action[0] === '-') {
              actions.push(<MenuItem key={'divider' + i} divider />)
          } else {
              actions.push(<MenuItem key={action[0]} eventKey={eventKey} onClick={e=> {this.createAction(action[0])}}>{action[1]}</MenuItem>)
              eventKey++;
          }
      }
      return(
        <div className="form-group">
          <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions">
            {actions}
          </DropdownButton>
        </div>
      );
  }


   componentDidMount() {
	this.fetchData(this.props.config, this.props.filters);
   }

   componentDidUpdate(prevProps, prevState, snapshot) {
       if (prevProps.from_date !==  this.props.from_date) {
		this.fetchData(this.props.config, this.props.filters);
       }
   }

    buildListUrlParams(page_params) {
         var page = page_params.pagination.page;
         var per_page = page_params.pagination.perPage;
         var sort = page_params.sort;
         var ordering = "";
    
    
         if (sort['asc']) {
            ordering=sort['id'];
         } else {
            ordering="-" + sort['id'];
         }
    
         return "ordering=" + ordering + "&page_size=" + per_page + "&page=" + page
    
    }
}
