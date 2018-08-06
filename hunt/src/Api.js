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
    	 this.createSuppress = this.createSuppress.bind(this);
    	 this.createThreshold = this.createThreshold.bind(this);
    	 this.createTag = this.createTag.bind(this);
    	 this.closeAction = this.closeAction.bind(this);
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

  createSuppress() {
	this.setState({action: {view: true, type: 'suppress'}});
  }

  createThreshold() {
	this.setState({action: {view: true, type: 'threshold'}});
  }
  
  createTag() {
	this.setState({action: {view: true, type: 'tag'}});
  }

  createTagKeep() {
	this.setState({action: {view: true, type: 'tagkeep'}});
  }

  closeAction() {
        this.setState({action: {view: false, type: 'suppress'}});
  }


  actionsButtons() {
      return(
	     <div className="form-group">
	         <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions">
		 <MenuItem eventKey="1" onClick={e => { this.createSuppress(); }}>Suppress</MenuItem>
		 <MenuItem eventKey="2" onClick={e => { this.createThreshold(); }}>Threshold</MenuItem>
		 <MenuItem divider />
		 <MenuItem eventKey="3" onClick={e => { this.createTag(); }}>Tag</MenuItem>
		 <MenuItem eventKey="4" onClick={e => { this.createTagKeep(); }}>Tag and Keep</MenuItem>
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
