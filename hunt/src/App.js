import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import PropTypes from 'prop-types';
import { ListView, ListViewItem, ListViewInfoItem, Row, Col, ListViewIcon } from 'patternfly-react';
import { VerticalNav, Dropdown, Icon, MenuItem, PaginationRow, Toolbar } from 'patternfly-react';
import { PAGINATION_VIEW, PAGINATION_VIEW_TYPES } from 'patternfly-react';
import { RuleFilter } from './Filter.js';
import { RuleSort } from './Sort.js';
import axios from 'axios';
import * as config from './config/Api.js';
import 'bootstrap3/dist/css/bootstrap.css'
import 'patternfly/dist/css/patternfly.css'
import 'patternfly/dist/css/patternfly-additions.css'
import 'patternfly-react/dist/css/patternfly-react.css'
import './App.css';

function onHomeClick() {
   ReactDOM.render(<RulesList />, document.getElementById('app-content'));
}

function onDashboardClick() {
   ReactDOM.render(<RulesList />, document.getElementById('app-content'));
}

function onHistoryClick() {

}

class HuntApp extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sources: [], rulesets: []
    };
    this.displaySource = this.displaySource.bind(this);
    this.displayRuleset = this.displayRuleset.bind(this);
  }

    componentDidMount() {
      axios.all([
          axios.get(config.API_URL + config.SOURCE_PATH),
          axios.get(config.API_URL + config.RULESET_PATH),
	  ])
      .then(axios.spread((SrcRes, RulesetRes) => {
         this.setState({ rulesets: RulesetRes.data['results'], sources: SrcRes.data['results']});
      }))
    }

    displayRuleset(ruleset) {
    	ReactDOM.render(<RulesetPage key={ruleset.pk} data={ruleset}/>, document.getElementById('app-content'));
    }
    
    displaySource(source) {
    	ReactDOM.render(<SourcePage key={source.pk} data={source} />, document.getElementById('app-content'));
    }


    render() {
        return(
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
            	    <VerticalNav.Masthead title="Scirius">
						<VerticalNav.Brand iconImg="/static/rules/stamus.png" titleImg="brand-alt.svg" />
						<VerticalNav.IconBar>
							<UserNavInfo/>
						</VerticalNav.IconBar>
					</VerticalNav.Masthead>
		   <VerticalNav.Item
            	      title="Home"
            	      iconClass="fa fa-home"
            	      initialActive
            	      onClick={onHomeClick}
            	      className={null}
            	    />

            	    <VerticalNav.Item
            	      title="Dashboards"
            	      iconClass="fa fa-tachometer"
            	      onClick={onDashboardClick}
            	      className={null}
            	    >
            	        <VerticalNav.Badge count={42} />
            	    </VerticalNav.Item>
            	    <VerticalNav.Item title="IDS rules" iconClass="glyphicon glyphicon-eye-open">
            	        <VerticalNav.SecondaryItem title="Sources" >
                	    {this.state.sources.map(function(source) {
				    return(
	    		     <VerticalNav.TertiaryItem key={source.pk} title={source.name}  onClick={this.displaySource.bind(this, source)}  />
			     )
			     }, this)}
	    		     <VerticalNav.TertiaryItem title="Add Source" href="/rules/source/add" />
            	        </VerticalNav.SecondaryItem>
       			<VerticalNav.SecondaryItem title="Rulesets">
                	    {this.state.rulesets.map(function(ruleset) {
				    return(
	    		     <VerticalNav.TertiaryItem key={ruleset.pk} title={ruleset.name} onClick={this.displayRuleset.bind(this, ruleset)} />
			     )
			     }, this)}
	    		     <VerticalNav.TertiaryItem title="Add Ruleset" href="/rules/ruleset/add" >
        			<Icon type="pf" name="help" />
			     </VerticalNav.TertiaryItem>
            	        </VerticalNav.SecondaryItem>
       	             </VerticalNav.Item>
       		     <VerticalNav.Item
		      title="History"
		      iconClass="glyphicon glyphicon-list"
            	      onClick={onHistoryClick}
		     />
       		     <VerticalNav.Item 
		       title="Setup"
		       iconClass="glyphicon glyphicon-cog"
		       href="/appliances"
		     />
       		</VerticalNav>
       		<div className="container-fluid container-cards-pf container-pf-nav-pf-vertical nav-pf-persistent-secondary">
       			<div className="row row-cards-pf">
			    <div className="col-xs-12 col-sm-12 col-md-12" id="app-content" >
	       	            </div>
       	         	</div>
       	        </div>
       	    </div>
        )
    }
}


class UserNavInfo extends Component {
	render() {
		return(
			<React.Fragment>
    			<Dropdown componentClass="li" id="help">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="help" />
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Help</MenuItem>
        				<MenuItem>About</MenuItem>
      				</Dropdown.Menu>
    			</Dropdown>
			    <Dropdown componentClass="li" id="time">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="fa" name="clock-o" /> Last 24h
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Last 1h</MenuItem>
        				<MenuItem>Last 6h</MenuItem>
    				</Dropdown.Menu>
			   </Dropdown>
			    <Dropdown componentClass="li" id="user">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="user" /> Eric Leblond
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Preferences</MenuItem>
        				<MenuItem>Logout</MenuItem>
    				</Dropdown.Menu>
			   </Dropdown>
			</React.Fragment>
		)
	}
}


class HuntPaginationRow extends Component {
  constructor(props) {
    super(props);
    this.onPageInput = this.onPageInput.bind(this);
    this.onPerPageSelect = this.onPerPageSelect.bind(this);
  };

  onPageInput = e => {
    const newPaginationState = Object.assign({}, this.props.pagination);
    newPaginationState.page = e.target.value;
    this.props.onPaginationChange(newPaginationState);
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


class RulesList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      rules: [], categories: [], rules_count: 0,
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [6, 10, 15, 25, 50]
      },
      filters: [],
      sort: {id: 'created', order: 'desc'}
    };
    this.fetchData = this.fetchData.bind(this);
    this.handlePaginationChange = this.handlePaginationChange.bind(this);
    this.onFirstPage = this.onFirstPage.bind(this);
    this.onNextPage = this.onNextPage.bind(this);
    this.onPrevPage = this.onPrevPage.bind(this);
    this.onLastPage = this.onLastPage.bind(this);
    this.UpdateFilter = this.UpdateFilter.bind(this);
    this.UpdateSort = this.UpdateSort.bind(this);
  }

  handlePaginationChange(pagin) {
     this.setState({pagination: pagin});
     this.fetchData(pagin.page, pagin.perPage, this.state.filters, this.state.sort);
  }

  onFirstPage() {
     const newPaginationState = Object.assign({}, this.state.pagination);
     newPaginationState.page = 1;
     this.setState({pagination: newPaginationState});
     this.fetchData(newPaginationState.page, newPaginationState.perPage, this.state.filters, this.state.sort);
  }

  onNextPage() {
     const newPaginationState = Object.assign({}, this.state.pagination);
     newPaginationState.page = newPaginationState.page + 1;
     this.setState({pagination: newPaginationState});
     this.fetchData(newPaginationState.page, newPaginationState.perPage, this.state.filters, this.state.sort);
  }

  onPrevPage() {
     const newPaginationState = Object.assign({}, this.state.pagination);
     newPaginationState.page = newPaginationState.page - 1;
     this.setState({pagination: newPaginationState});
     this.fetchData(newPaginationState.page, newPaginationState.perPage, this.state.filters, this.state.sort);
  }

  onLastPage() {
     const newPaginationState = Object.assign({}, this.state.pagination);
     newPaginationState.page = Math.floor(this.state.rules_count / this.state.pagination.perPage) + 1;
     this.setState({pagination: newPaginationState});
     this.fetchData(newPaginationState.page, newPaginationState.perPage, this.state.filters, this.state.sort);
  }

   UpdateFilter(filters) {
     this.setState({filters: filters});
     this.fetchData(this.state.pagination.page, this.state.pagination.perPage, filters, this.state.sort);
   }

   UpdateSort(sort) {
     this.setState({sort: sort});
     this.fetchData(this.state.pagination.page, this.state.pagination.perPage, this.state.filters, sort);
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

  fetchData(page, per_page, filters, sort) {
     var string_filters = this.buildFilter(filters);
     var ordering = "";

     if (sort['asc']) {
        ordering=sort['id'];
     } else {
        ordering="-" + sort['id'];
     }

     axios.all([
          axios.get(config.API_URL + config.RULE_PATH + "?ordering=" + ordering + "&page_size=" + per_page + "&page=" + page + string_filters),
          axios.get(config.API_URL + config.CATEGORY_PATH + "?page_size=100"),
	  ])
      .then(axios.spread((RuleRes, CatRes) => {
	 var categories_array = CatRes.data['results'];
	 var categories = {};
	 for (var i = 0; i < categories_array.length; i++) {
	     var cat = categories_array[i];
	     categories[cat.pk] = cat;
	 }
         this.setState({ rules_count: RuleRes.data['count'], rules: RuleRes.data['results'], categories: categories});
     }))
  }

  componentDidMount() {
      this.fetchData(this.state.pagination.page, this.state.pagination.perPage, this.state.filters, this.state.sort)
  }
  
  render() {
    var state = this.state;
    return (
        <div className="RulesList">
	<Toolbar>
	    <RuleFilter UpdateFilter={this.UpdateFilter} />
	    <RuleSort UpdateSort={this.UpdateSort} />
      </Toolbar>
	    <ListView>
            {this.state.rules.map(function(rule) {
                return(
                   <RuleInList key={rule.pk} data={rule} state={state}/>
                )
             })}
	    </ListView>
	    <HuntPaginationRow
	        viewType = {PAGINATION_VIEW.LIST}
	        pagination={this.state.pagination}
	        onPaginationChange={this.handlePaginationChange}
		amountOfPages = {Math.ceil(this.state.rules_count / this.state.pagination.perPage)}
		pageInputValue = {this.state.pagination.page}
		itemCount = {this.state.rules_count}
		itemsStart = {(this.state.pagination.page - 1) * this.state.pagination.perPage}
		itemsEnd = {Math.min(this.state.pagination.page * this.state.pagination.perPage - 1, this.state.rules_count) }
		onFirstPage={this.onFirstPage}
		onNextPage={this.onNextPage}
		onPreviousPage={this.onPrevPage}
		onLastPage={this.onLastPage}

	    />
        </div>
    );
  }
}

class RuleInList extends Component {
  handleClick = () => {
    //this.setState({rule: {this.props.data}});
    const rdata = <RulePage rule={this.props.data}/>
    ReactDOM.render(rdata, document.getElementById('app-content'));
  }
  render() {
    var category = this.props.state.categories[this.props.data.category];
    return (
	<ListViewItem
  actions={<button onClick={this.handleClick}>View</button>}
  leftContent={<ListViewIcon name="envelope" />}
  additionalInfo={[<ListViewInfoItem key="created"><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="updated"><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="category"><p>Category: {category.name}</p></ListViewInfoItem>
  ]}
  heading={this.props.data.sid}
  description={this.props.data.msg}
>
<Row>
<Col sm={11}>
{this.props.data.content}
</Col>
</Row>
</ListViewItem>
    )
  }
}


class RulePage extends Component {
    render() {
        return (
            <h1>{this.props.rule.msg}</h1>
	)
    }
}

class SourcePage extends Component {
    render() {
	var source = this.props.data;
        return (
            <h1>{source.name}</h1>
	)
    }
}

class RulesetPage extends Component {
    render() {
	var ruleset = this.props.data;
        return (
            <h1>{ruleset.name}</h1>
	)
    }
}

export default HuntApp;
