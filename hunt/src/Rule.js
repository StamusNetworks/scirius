import React from 'react';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import axios from 'axios';
import { PAGE_STATE } from './Const.js';
import { PAGINATION_VIEW } from 'patternfly-react';
import { SciriusChart } from './Chart.js';
import * as config from './config/Api.js';
import { ListGroup, ListGroupItem, Badge } from 'react-bootstrap';
import { HuntFilter } from './Filter.js';
import { HuntList, HuntPaginationRow } from './Api.js';


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
  }, {
    id: 'probe',
    title: 'Probe',
    placeholder: 'Filter hits by Probe',
    filterType: 'text'
  }, {
    id: 'sprobe',
    title: 'Check Probe',
    placeholder: 'Filter hits by Probe',
    filterType: 'select',
    filterValues: [{title: 'sn-probe-1', id:'sn-probe-1'}, {title: 'infra1', id:'infra1'}] 
  }
];

export const RuleSortFields = [
  {
    id: 'created',
    title: 'Created',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'hits',
    title: 'Alerts',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'msg',
    title: 'Message',
    isNumeric: false,
    defaultAsc: true,
  },
  {
    id: 'updated',
    title: 'Updated',
    isNumeric: true,
    defaultAsc: false,
  }
];

export class RuleInList extends React.Component {
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
      {this.props.data.timeline &&
<Row>
<Col sm={11}>
<div className="container-fluid">
   <div className="row">
      <div className="col-md-10">
      <SciriusChart data={ this.props.data.timeline }
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                     } }
                    }
		from_date = {this.props.from_date}
      />
      </div>
      <div className="col-md-2">
         <h4>Probes</h4>
         <ListGroup>
	    {this.props.data.probes.map( item => {
		return(<ListGroupItem key={item.probe}>
		 {item.probe}     
		 <Badge>{item.hits}</Badge>
		 </ListGroupItem>)
	    })}
         </ListGroup>
      </div>
   </div>
</div>
</Col>
</Row>
      }
</ListViewItem>
    )
  }
}

export class RuleCard extends React.Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    var imported = undefined;
    if (!this.props.data.created) {
    	imported = this.props.data.imported_date.split("T")[0];
    }
    return (
    <div className="col-xs-6 col-sm-4 col-md-4">
	<div className="card-pf rule-card">
       <div className="card-pf-heading">
           <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.data.msg}>{this.props.data.msg}</h2>
       </div>
       <div className="card-pf-body">
            <div className="container-fluid">
               <div className="row">
                  <div className="col-md-5 truncate-overflow"  data-toggle="tooltip" title={category.name}>Cat: {category.name}</div>
                  <div className="col-md-4">
                    {this.props.data.created &&
                  <p>Created: {this.props.data.created}</p>
                    }
                    {!this.props.data.created &&
                  <p>Imported: {imported}</p>
                    }
                  </div>
                  <div className="col-md-3">Alerts 
                     <Spinner loading={this.props.data.hits === undefined} size="xs">
                         <span className="badge">{this.props.data.hits}</span>
                     </Spinner>
                  </div>
                </div>
           </div>
           <Spinner loading={this.props.data.hits === undefined} size="xs">
      {this.props.data.timeline &&
      <div className="chart-pf-sparkline">
      <SciriusChart data={ this.props.data.timeline }
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            show: false
                     },
                     y: { show: false }
               }}
               legend = {{
                  show: false    
               }}
               size = {{ height: 50 }}
               point = {{ show: false }}
               from_date = {this.props.from_date}
      />
      </div>
      }
      {!this.props.data.timeline &&
          <div className="no-sparkline">
             <p>No alert</p>
          </div>
      }
           </Spinner>
         <div>
            SID: <strong>{this.props.data.sid}</strong>
            <span className="pull-right"><button onClick={this.props.SwitchPage.bind(this, PAGE_STATE.rule).bind(this, this.props.data)}>View</button></span>
         </div>
      </div>
   </div>
   </div>
    )
  }
}

export class RulePage extends React.Component {
    constructor(props) {
        super(props);
        var rule = JSON.parse(JSON.stringify(this.props.rule));
	if (typeof rule === 'number') {
            this.state = { rule: undefined, sid: rule};
	} else {
	    rule.timeline = undefined;
            this.state = { rule: rule, sid: rule.sid};
	}
        this.updateRuleState = this.updateRuleState.bind(this);
    }

    componentDidMount() {
       var rule = this.state.rule;
       var sid = this.state.sid;
       if (rule !== undefined) {
           updateHitsStats([rule], this.props.from_date, this.updateRuleState, undefined);
       } else {
           axios.get(config.API_URL + config.RULE_PATH + sid).then(
		res => { 
                         updateHitsStats([res.data], this.props.from_date, this.updateRuleState, undefined);
		}
	   )
       }
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if (prevProps.from_date !==  this.props.from_date) {
            var rule = JSON.parse(JSON.stringify(this.props.rule));
            updateHitsStats([rule], this.props.from_date, this.updateRuleState, undefined);
       }
    }

    updateRuleState(rule) {
        this.setState({rule: rule[0]});
    }

    render() {
        return (
            <div>
	    <Spinner loading={this.state.rule === undefined}>
	    {this.state.rule &&
            <div>
	    <h1>{this.state.rule.msg}</h1>
            <div className='container-fluid container-cards-pf'>
                <div className='row'>
                     <p>{this.state.rule.content}</p>
                     {this.state.rule.timeline &&
                        <SciriusChart data={ this.state.rule.timeline }
                            axis={{ x: { type: 'timeseries',
                                    localtime: true,
                                    min: this.props.from_date,
                                    max: Date.now(),
                                    tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                                    }
                                   }
                                 }
                            from_date = {this.props.from_date}
                         />
                      }
                </div>
                <div className='row row-cards-pf'>
                    <RuleStat title="Sources" rule={this.state.rule} item='src' from_date={this.props.from_date} />
                    <RuleStat title="Destinations" rule={this.state.rule} item='dest' from_date={this.props.from_date} />
                    <RuleStat title="Probes" rule={this.state.rule} item='probe' from_date={this.props.from_date} />
                </div>
            </div>
	    </div>
	    }
	    </Spinner>
            </div>
	)
    }
}

class RuleStat extends React.Component {
    constructor(props) {
	    super(props);
  	    this.state = {data: []};
        this.updateData = this.updateData.bind(this);
    }

    updateData() {
          axios.get(config.API_URL + config.ES_BASE_PATH +
                    'rule_' + this.props.item + '&from_date=' + this.props.from_date +
                    '&sid=' + this.props.rule.sid)
             .then(res => {
               this.setState({ data: res.data });
            })
    }

    componentDidMount() {
            this.updateData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if (prevProps.from_date !==  this.props.from_date) {
               this.updateData();
       }
    }

    render() {
        return (
	    <div className="col-xs-6 col-sm-4 col-md-3">
	<div className="card-pf rule-card">
       <div className="card-pf-heading">
           <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.title}>{this.props.title}</h2>
       </div>
       <div className="card-pf-body">
	<ListGroup>
	    {this.state.data.map( item => {
		return(<ListGroupItem key={item.key}>
		 {item.key}     
		 <Badge>{item.doc_count}</Badge>
		 </ListGroupItem>)
	    })}
	</ListGroup>
	</div>
        </div>
	</div>);
    }
}

function buildProbesSet(data) {
    var probes = [];
    for (var probe in data) {
	probes.push({probe: data[probe].key, hits: data[probe].doc_count});
    }
    return probes;
}

function buildTimelineDataSet(tdata) {
    var timeline = {x : 'x', type: 'area',  columns: [['x'], ['alerts']]};
    for (var key in tdata) {
        timeline.columns[0].push(tdata[key].key);
        timeline.columns[1].push(tdata[key].doc_count);
    }
    return timeline;
}

export function updateHitsStats(rules, p_from_date, updateCallback, qfilter) {
         var sids = Array.from(rules, x => x.sid).join()
	     var from_date = "&from_date=" + p_from_date;
         var url = config.API_URL + config.ES_SIGS_LIST_PATH + sids + from_date;
	 if (qfilter) {
	     url += "&filter=" + qfilter;
	 }
         axios.get(url).then(res => {
                 /* we are going O(n2), we should fix that */
                 for (var rule in rules) {
                    var found = false;
                    for (var info in res.data) {
                        if (res.data[info].key === rules[rule].sid) {
                            rules[rule].timeline = buildTimelineDataSet(res.data[info].timeline['buckets']);
                            rules[rule].probes = buildProbesSet(res.data[info].probes['buckets']);
                            rules[rule].hits = res.data[info].doc_count;
                            found = true;
                            break;
                        }
                    }
                    if (found === false) {
                        rules[rule].hits = 0;
                        rules[rule].probes = [];
                        rules[rule].timeline = undefined;
                    }
                 }
                 if (updateCallback) {
                    updateCallback(rules);
                 }
         });
}

export class RulesList extends HuntList {
  constructor(props) {
    super(props);
    this.state = {
      rules: [], categories: [], rules_count: 0,
      loading: true,
      refresh_data: false,
    };
    this.updateRulesState = this.updateRulesState.bind(this);
    this.fetchHitsStats = this.fetchHitsStats.bind(this);
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
     if (prevProps.from_date !==  this.props.from_date) {
             this.fetchHitsStats(this.state.rules);
     }
  }

   buildQFilter(filters) {
     var qfilter = [];
     for (var i=0; i < filters.length; i++) {
	if (filters[i].id === 'probe') {
            qfilter.push('host.raw:' + filters[i].value);
	    continue;
	} else if (filters[i].id === 'sprobe') {
            qfilter.push('host.raw:' + filters[i].value.id);
	    continue;
	}
     }
     if (qfilter.length === 0) {
	 return undefined;
     }
     return qfilter.join(" AND ");
   }

   buildFilter(filters) {
     var l_filters = {};
     for (var i=0; i < filters.length; i++) {
	if (filters[i].id !== 'probe') {
               if (filters[i].id in l_filters) {
               l_filters[filters[i].id] += "," + filters[i].value;
            } else {
               l_filters[filters[i].id] = filters[i].value;
            }
	}
     }
     var string_filters = "";
     for (var k in l_filters) {
         string_filters += "&" + k + "=" + l_filters[k];
     }
     var qfilter = this.buildQFilter(filters);
     if (qfilter) {
	 string_filters += '&qfilter=' +  qfilter;
     }
     return string_filters;
   }

  updateRulesState(rules) {
         this.setState({rules: rules});
  }

  buildTimelineDataSet(tdata) {
    var timeline = {x : 'x', type: 'area',  columns: [['x'], ['alerts']]};
    for (var key in tdata) {
        timeline.columns[0].push(tdata[key].date);
        timeline.columns[1].push(tdata[key].hits);
    }
    return timeline;
  }

  buildHitsStats(rules) {
       for (var rule in rules) {
          rules[rule].timeline = this.buildTimelineDataSet(rules[rule].timeline_data);
	  rules[rule].timeline_data = undefined;
       }
       this.updateRulesState(rules);
   }

  fetchHitsStats(rules) {
	 var qfilter = this.buildQFilter(this.props.config.filters);
     updateHitsStats(rules, this.props.from_date, this.updateRulesState, qfilter);
  }

  fetchData(rules_stat) {
     var filters = rules_stat.filters;
     var string_filters = this.buildFilter(filters);

     this.setState({refresh_data: true});
     axios.all([
          axios.get(config.API_URL + config.RULE_PATH + this.buildListUrlParams(rules_stat) + "&from_date=" + this.props.from_date + string_filters),
          axios.get(config.API_URL + config.CATEGORY_PATH + "?page_size=100"),
	  ])
      .then(axios.spread((RuleRes, CatRes) => {
	 var categories_array = CatRes.data['results'];
	 var categories = {};
	 for (var i = 0; i < categories_array.length; i++) {
	     var cat = categories_array[i];
	     categories[cat.pk] = cat;
	 }
         this.setState({ rules_count: RuleRes.data['count'], rules: RuleRes.data['results'], categories: categories, loading: false, refresh_data: false});
	 if (!RuleRes.data.results[0].timeline_data) {
	     this.fetchHitsStats(RuleRes.data['results']);
	 } else {
             this.buildHitsStats(RuleRes.data['results']);
	 }
     }))
  }

  componentDidMount() {
      this.fetchData(this.props.config)
  }
  
  render() {
    return (
        <div className="RulesList">
	<Spinner loading={this.state.loading} >
	    <HuntFilter ActiveFilters={this.props.config.filters}
	          config={this.props.config}
		  ActiveSort={this.props.config.sort}
		  UpdateFilter={this.UpdateFilter}
		  UpdateSort={this.UpdateSort}
		  setViewType={this.setViewType}
		  filterFields={RuleFilterFields}
		  sort_config={RuleSortFields}
		  displayToggle={true}
            />
            {this.props.config.view_type === 'list' &&
	    <ListView>
            {this.state.rules.map(function(rule) {
                return(
                   <RuleInList key={rule.pk} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.props.SwitchPage} />
                )
             },this)}
	    </ListView>
            }
            {this.props.config.view_type === 'card' &&
                <div className='container-fluid container-cards-pf'>
                <div className='row row-cards-pf'>
                {this.state.rules.map(function(rule) {
                         return(
                                <RuleCard key={rule.pk} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.props.SwitchPage} />
                )
             },this)}
                </div>
                </div>
            }
	    <HuntPaginationRow
	        viewType = {PAGINATION_VIEW.LIST}
	        pagination={this.props.config.pagination}
	        onPaginationChange={this.handlePaginationChange}
		amountOfPages = {Math.ceil(this.state.rules_count / this.props.config.pagination.perPage)}
		pageInputValue = {this.props.config.pagination.page}
		itemCount = {this.state.rules_count}
		itemsStart = {(this.props.config.pagination.page - 1) * this.props.config.pagination.perPage}
		itemsEnd = {Math.min(this.props.config.pagination.page * this.props.config.pagination.perPage - 1, this.state.rules_count) }
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
