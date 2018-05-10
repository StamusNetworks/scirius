import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { ListView, ListViewItem, ListViewInfoItem, Row, Col, ListViewIcon } from 'patternfly-react';
import { VerticalNav, Dropdown, Icon, MenuItem, PaginationRow, Toolbar, Spinner } from 'patternfly-react';
import { AboutModal } from 'patternfly-react';
import { PAGINATION_VIEW, PAGINATION_VIEW_TYPES } from 'patternfly-react';
import C3Chart from 'react-c3js';
import 'c3/c3.css';
import { RuleFilter } from './Filter.js';
import axios from 'axios';
import * as config from './config/Api.js';
import 'bootstrap3/dist/css/bootstrap.css'
import 'patternfly/dist/css/patternfly.css'
import 'patternfly/dist/css/patternfly-additions.css'
import 'patternfly-react/dist/css/patternfly-react.css'
import './App.css';

const PAGE_STATE = {
   rules_list: 'RULES_LIST',
   source: 'SOURCE',
   ruleset: 'RULESET',
   rule: 'RULE',
};

class HuntApp extends Component {
  constructor(props) {
    super(props);
    var duration = localStorage.getItem('duration');
    if (!duration) {
	duration = 24;
    }
    this.state = {
      sources: [], rulesets: [], duration: duration, from_date: (Date.now() - duration * 3600 * 1000),
      display: { page: PAGE_STATE.rules_list, item:undefined },
      rules_list: {
        pagination: {
          page: 1,
          perPage: 6,
          perPageOptions: [6, 10, 15, 25, 50]
        },
        filters: [],
        sort: {id: 'created', asc: false},
      }
    };
    this.displaySource = this.displaySource.bind(this);
    this.displayRuleset = this.displayRuleset.bind(this);
    this.changeDuration = this.changeDuration.bind(this);

    this.fromDate = this.fromDate.bind(this);

    this.onHomeClick = this.onHomeClick.bind(this);
    this.onDashboardClick = this.onDashboardClick.bind(this);
    this.onHistoryClick = this.onHistoryClick.bind(this);
    this.switchPage = this.switchPage.bind(this);
    this.updateRuleListState = this.updateRuleListState.bind(this);
    
  }

    onHomeClick() {
        this.setState({display: {page: PAGE_STATE.rules_list}});
    }
    
    
    onDashboardClick() {
        this.setState({display: {page: PAGE_STATE.rules_list}});
    }
    
    onHistoryClick() {
    
    }

    fromDate(period) {
	const duration = period * 3600 * 1000;
	return Date.now() - duration;
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
        this.setState({display: {page:'RULESET', item: ruleset}});
    }
    
    displaySource(source) {
        this.setState({display: {page:'SOURCE', item: source}});
    }

   changeDuration(period) {
	this.setState({ duration: period, from_date: this.fromDate(period)});
	localStorage.setItem('duration', period);
   }

  switchPage(page, item) {
        this.setState({display: {page: page, item: item}});
  }
 
    updateRuleListState(rules_list_state) {
        this.setState({rules_list: rules_list_state});
    }

    render() {
            var displayed_page = undefined;
            switch (this.state.display.page) {
               case PAGE_STATE.rules_list:
                  displayed_page = <RulesList rules_list={this.state.rules_list} from_date={this.state.from_date} SwitchPage={this.switchPage} updateRuleListState={this.updateRuleListState} />
                  break;
               case PAGE_STATE.source:
                  displayed_page = <SourcePage source={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.ruleset:
                  displayed_page = <RulesetPage ruleset={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.rule:
                  displayed_page = <RulePage rule={this.state.display.item} from_date={this.state.from_date}/>
                  break;
            }
        return(
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
            	    <VerticalNav.Masthead title="Scirius">
						<VerticalNav.Brand iconImg="/static/rules/stamus.png" titleImg="brand-alt.svg" />
						<VerticalNav.IconBar>
							<UserNavInfo ChangeDuration={this.changeDuration} period={this.state.duration}/>
						</VerticalNav.IconBar>
					</VerticalNav.Masthead>
		   <VerticalNav.Item
            	      title="Home"
            	      iconClass="fa fa-home"
            	      initialActive
            	      onClick={this.onHomeClick}
            	      className={null}
            	    />

            	    <VerticalNav.Item
            	      title="Dashboards"
            	      iconClass="fa fa-tachometer"
            	      onClick={this.onDashboardClick}
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
            	      onClick={this.onHistoryClick}
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
                                {displayed_page}
	       	            </div>
       	         	</div>
       	        </div>
       	    </div>
        )
    }
}


const USER_PERIODS = {
  1: '1h',
  6: '6h',
  24: '24h',
  48: '2d',
  168: '7d',
  720: '30d'
};

class UserNavInfo extends Component {
  constructor(props) {
    super(props);
    this.state = {
	    showModal: false
    }
    this.AboutClick = this.AboutClick.bind(this);
    this.closeModal = this.closeModal.bind(this);
  }

  AboutClick(e) {
	  this.setState({showModal: true});
  }
  closeModal(e) {
	  this.setState({showModal: false});
  }

	render() {
		return(
			<React.Fragment>
    			<Dropdown componentClass="li" id="help">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="help" />
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Help</MenuItem>
        				<MenuItem onClick={this.AboutClick}>About</MenuItem>
      				</Dropdown.Menu>
    			</Dropdown>
			    <Dropdown componentClass="li" id="time">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="fa" name="clock-o" /> Last {USER_PERIODS[this.props.period]}
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
				        {Object.keys(USER_PERIODS).map((period) => {
        				return (<MenuItem key={period} onClick={this.props.ChangeDuration.bind(this, period)}>Last {USER_PERIODS[period]}</MenuItem>)
					}, this)}
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
			   
        <AboutModal
          show={this.state.showModal}
          onHide={this.closeModal}
          productTitle="Scirius Enterprise Edition"
          //logo={logo}
          altLogo="SEE Logo"
          trademarkText="Copyright 2014-2018, Stamus Networks"
        >
          <AboutModal.Versions>
            <AboutModal.VersionItem label="Version" versionText="31.0.0" />
          </AboutModal.Versions>
        </AboutModal>
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
      loading: true
    };
    this.fetchData = this.fetchData.bind(this);
    this.fetchHitsStats = this.fetchHitsStats.bind(this);
    this.handlePaginationChange = this.handlePaginationChange.bind(this);
    this.onFirstPage = this.onFirstPage.bind(this);
    this.onNextPage = this.onNextPage.bind(this);
    this.onPrevPage = this.onPrevPage.bind(this);
    this.onLastPage = this.onLastPage.bind(this);
    this.UpdateFilter = this.UpdateFilter.bind(this);
    this.UpdateSort = this.UpdateSort.bind(this);
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
     if (prevProps.from_date !=  this.props.from_date) {
             this.fetchHitsStats(this.state.rules);
     }
  }

  handlePaginationChange(pagin) {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.pagination = pagin;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
  }

  onFirstPage() {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.pagination.page = 1;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
  }

  onNextPage() {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.pagination.page = newRuleState.pagination.page + 1;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
  }

  onPrevPage() {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.pagination.page = newRuleState.pagination.page - 1;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
  }

  onLastPage() {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.pagination.page = Math.floor(this.state.rules_count / this.props.rules_list.pagination.perPage) + 1;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
  }

   UpdateFilter(filters) {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.filters = filters;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
   }

   UpdateSort(sort) {
     const newRuleState = Object.assign({}, this.props.rules_list);
     newRuleState.sort = sort;
     this.props.updateRuleListState(newRuleState);
     this.fetchData(newRuleState);
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

  buildTimelineDataSet(data) {
    var tdata = data['buckets'];
    var timeline = {x : 'x', type: 'bar',  columns: [['x'], ['alerts']]};
    for (var key in tdata) {
        timeline.columns[0].push(tdata[key].key);
        timeline.columns[1].push(tdata[key].doc_count);
    }
    return timeline;
  }

  fetchHitsStats(rules) {
         var sids = Array.from(rules, x => x.sid).join()
	 var from_date = "&from_date=" + this.props.from_date;
         axios.get(config.API_URL + config.ES_SIGS_LIST_PATH + sids + from_date).then(res => {
                 /* we are going O(n2), we should fix that */
                 for (var rule in rules) {
                    for (var info in res.data) {
                        if (res.data[info].key === rules[rule].sid) {
                            rules[rule].timeline = this.buildTimelineDataSet(res.data[info].timeline);
                            rules[rule].hits = res.data[info].doc_count;
                            break;
                        }
                    }
                    if (rules[rule].hits === undefined) {
                        rules[rule].hits = 0;
                        rules[rule].timeline = undefined;
                    }
                 }
                 this.setState({rules: rules});
         })

  }

  fetchData(rules_stat) {
     var page = rules_stat.pagination.page;
     var per_page = rules_stat.pagination.perPage;
     var filters = rules_stat.filters;
     var sort = rules_stat.sort;
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
         this.setState({ rules_count: RuleRes.data['count'], rules: RuleRes.data['results'], categories: categories, loading: false});
	 this.fetchHitsStats(RuleRes.data['results']);
     }))
  }

  componentDidMount() {
      this.fetchData(this.props.rules_list)
  }
  
  render() {
    return (
        <div className="RulesList">
	<Spinner loading={this.state.loading} >
	<Toolbar>
	    <RuleFilter ActiveFilters={this.props.rules_list.filters} ActiveSort={this.props.rules_list.sort} UpdateFilter={this.UpdateFilter}  UpdateSort={this.UpdateSort} />
      </Toolbar>
	    <ListView>
            {this.state.rules.map(function(rule) {
                return(
                   <RuleInList key={rule.pk} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.props.SwitchPage} />
                )
             },this)}
	    </ListView>
	    <HuntPaginationRow
	        viewType = {PAGINATION_VIEW.LIST}
	        pagination={this.props.rules_list.pagination}
	        onPaginationChange={this.handlePaginationChange}
		amountOfPages = {Math.ceil(this.state.rules_count / this.props.rules_list.pagination.perPage)}
		pageInputValue = {this.props.rules_list.pagination.page}
		itemCount = {this.state.rules_count}
		itemsStart = {(this.props.rules_list.pagination.page - 1) * this.props.rules_list.pagination.perPage}
		itemsEnd = {Math.min(this.props.rules_list.pagination.page * this.props.rules_list.pagination.perPage - 1, this.state.rules_count) }
		onFirstPage={this.onFirstPage}
		onNextPage={this.onNextPage}
		onPreviousPage={this.onPrevPage}
		onLastPage={this.onLastPage}

	    />
	    </Spinner>
        </div>
    );
  }
}

class RuleInList extends Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    return (
	<ListViewItem
  actions={<button onClick={this.props.SwitchPage.bind(this, PAGE_STATE.rule).bind(this, this.props.data)}>View</button>}
  leftContent={<ListViewIcon name="envelope" />}
  additionalInfo={[<ListViewInfoItem key="created"><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="updated"><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="category"><p>Category: {category.name}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="hits"><Spinner loading={this.props.data.hits === undefined} size="xs"><p>Alerts <span className="badge">{this.props.data.hits}</span></p></Spinner></ListViewInfoItem>
  ]}
  heading={this.props.data.sid}
  description={this.props.data.msg}
>
<Row>
<Col sm={11}>
<p>{this.props.data.content}</p>
      {this.props.data.timeline &&
      /* FIXME we should be dynamic on the width, auto don't work if we have just a few data */
      <C3Chart data={ this.props.data.timeline } bar={{width: 10}}
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                     } }
                    }
      />
      }
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
	var source = this.props.source;
        return (
            <h1>{source.name}</h1>
	)
    }
}

class RulesetPage extends Component {
    render() {
	var ruleset = this.props.ruleset;
        return (
            <h1>{ruleset.name}</h1>
	)
    }
}

export default HuntApp;
