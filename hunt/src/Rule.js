import React from 'react';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import axios from 'axios';
import { PAGINATION_VIEW } from 'patternfly-react';
import { Modal, DropdownKebab, MenuItem, Icon, Button, DropdownButton } from 'patternfly-react';
import { Form, FormGroup, FormControl } from 'patternfly-react';
import { SciriusChart } from './Chart.js';
import * as config from './config/Api.js';
import { ListGroup, ListGroupItem, Badge } from 'react-bootstrap';
import { HuntFilter } from './Filter.js';
import { HuntList, HuntPaginationRow } from './Api.js';
import { HuntDashboard } from './Dashboard.js';
import { EventValue } from './Event.js';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';


export const RuleFilterFields = [
  {
    id: 'alert.tag',
    title: 'Tag',
    placeholder: 'Filter by Tag',
    filterType: 'select',
    filterValues: [{title: 'Untagged', id:'untagged'}, {title: 'Relevant', id:'relevant'}, {title: 'Informational', id:'informational'}] 
  },
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
    id: 'alert.signature_id',
    title: 'Signature ID',
    placeholder: 'Filter by Signature',
    filterType: 'text'
  }, {
    id: 'dns.query.rrname',
    title: 'DNS RRName',
    placeholder: 'Filter by DNS Query',
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
    var category = this.props.data.category;
    var source = this.props.state.sources[category.source];
    var cat_tooltip = category.name;
    if (source && source.name) {
	    cat_tooltip = source.name + ": " + category.name;
    }
    var kebab_config = { rule: this.props.data };
    return (
	<ListViewItem
	   key={this.props.data.sid}
  actions={[<a key={"actions-" + this.props.data.sid} onClick={e => {this.props.SwitchPage(this.props.data)}}><Icon type="fa" name="search-plus"/> </a>, <RuleEditKebab key={"kebab-" + this.props.data.sid} config={kebab_config}/> ]}
  leftContent={<ListViewIcon name="envelope" />}
  additionalInfo={[<ListViewInfoItem key={"created-" + this.props.data.sid} ><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                   <ListViewInfoItem key={"updated-" + this.props.data.sid}><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                   <ListViewInfoItem key={"category-" + this.props.data.sid}><p  data-toggle="tooltip" title={cat_tooltip}>Category: {category.name}</p></ListViewInfoItem>,
                   <ListViewInfoItem key={"hits-" + this.props.data.sid}><Spinner loading={this.props.data.hits === undefined} size="xs"><p>Alerts <span className="badge">{this.props.data.hits}</span></p></Spinner></ListViewInfoItem>
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
    var category = this.props.data.category;
    var source = this.props.state.sources[category.source];
    var cat_tooltip = category.name;
    if (source && source.name) {
	    cat_tooltip = source.name + ": " + category.name;
    }
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
                  <div className="col-md-5 truncate-overflow"  data-toggle="tooltip" title={cat_tooltip}>Cat: {category.name}</div>
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
            <span className="pull-right"><a onClick={e => {this.props.SwitchPage(this.props.data)}}><Icon type="fa" name="search-plus"/> </a></span>
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
            this.state = { rule: undefined, sid: rule, toggle: { show: false, action: "Disable" }, extinfo: { http: false, dns: false, tls: false }};
	} else {
	    rule.timeline = undefined;
            this.state = { rule: rule, sid: rule.sid, toggle: { show: false, action: "Disable" }, extinfo: { http: false, dns: false, tls: false }};
	}
        this.updateRuleState = this.updateRuleState.bind(this);
        this.updateExtInfo = this.updateExtInfo.bind(this);
    }

    updateExtInfo(data) {
	    if (!data) {
		    return;
	    }
	       var extinfo = this.state.extinfo;
	       for (var i=0; i < data.length; i++) {
                    if (data[i].key === "dns") {
                         extinfo.dns = true;
		    }
                    if (data[i].key === "http") {
                         extinfo.http = true;
		    }
                    if (data[i].key === "tls") {
                         extinfo.tls = true;
		    }
	       }
	       this.setState({extinfo: extinfo});
    }

    componentDidMount() {
       var rule = this.state.rule;
       var sid = this.state.sid;
       var qfilter = buildQFilter(this.props.filters);
       if (rule !== undefined) {
           updateHitsStats([rule], this.props.from_date, this.updateRuleState, qfilter);
	   axios.get(config.API_URL + config.ES_BASE_PATH +
                    'field_stats&field=app_proto&from_date=' + this.props.from_date +
                    '&sid=' + this.props.rule.sid)
             .then(res => {
		     this.updateExtInfo(res.data);
            }) 
       } else {
           axios.get(config.API_URL + config.RULE_PATH + sid).then(
		res => { 
                         updateHitsStats([res.data], this.props.from_date, this.updateRuleState, qfilter);
	   axios.get(config.API_URL + config.ES_BASE_PATH +
                    'field_stats&field=app_proto&from_date=' + this.props.from_date +
                    '&sid=' + sid)
             .then(res => {
		     this.updateExtInfo(res.data);
            }) 
		}
	   )
       }
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       var qfilter = buildQFilter(this.props.filters);
       if ((prevProps.from_date !==  this.props.from_date) ||
           (prevProps.filters.length !==  this.props.filters.length)) {
            var rule = JSON.parse(JSON.stringify(this.state.rule));
            updateHitsStats([rule], this.props.from_date, this.updateRuleState, qfilter);
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
	    <h1>{this.state.rule.msg}
            <span className="pull-right"> 
                <RuleEditKebab config={this.state} />
            </span>
        </h1>
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
                    <HuntStat title="Sources" rule={this.state.rule} config={this.props.config} filters={this.props.filters}  item='src_ip' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                    <HuntStat title="Destinations" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='dest_ip' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                    <HuntStat title="Probes" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='host' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                </div>
		{this.state.extinfo.http &&
                <div className='row row-cards-pf'>
                    <HuntStat title="Hostname" rule={this.state.rule}  config={this.props.config} filters={this.props.filters}  item='http.hostname' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                    <HuntStat title="URL" rule={this.state.rule}  config={this.props.config} filters={this.props.filters}  item='http.url' from_date={this.props.from_date}  UpdateFilter={this.props.UpdateFilter}/>
                    <HuntStat title="User agent" rule={this.state.rule}  config={this.props.config} filters={this.props.filters}  item='http.http_user_agent' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                </div>
		}
		{this.state.extinfo.dns &&
                <div className='row row-cards-pf'>
                    <HuntStat title="Name" rule={this.state.rule}  config={this.props.config} filters={this.props.filters} item='dns.query.rrname' from_date={this.props.from_date}  UpdateFilter={this.props.UpdateFilter} />
                    <HuntStat title="Type" rule={this.state.rule}  config={this.props.config} filters={this.props.filters}  item='dns.query.rrtype' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                </div>
		}
		{this.state.extinfo.tls &&
                <div className='row row-cards-pf'>
                    <HuntStat title="Subject DN" rule={this.state.rule}  config={this.props.config} filters={this.props.filters} item='tls.subject' from_date={this.props.from_date}  UpdateFilter={this.props.UpdateFilter} />
                    <HuntStat title="SNI" rule={this.state.rule}  config={this.props.config} filters={this.props.filters} item='tls.sni' from_date={this.props.from_date}  UpdateFilter={this.props.UpdateFilter} />
                    <HuntStat title="Fingerprint" rule={this.state.rule}  config={this.props.config} filters={this.props.filters}  item='tls.fingerprint' from_date={this.props.from_date} UpdateFilter={this.props.UpdateFilter}/>
                </div>
		}
            </div>
	    </div>
	    }
	    </Spinner>
            </div>
	)
    }
}

export class HuntStat extends React.Component {
    constructor(props) {
	    super(props);
  	    this.state = {data: []};
        this.updateData = this.updateData.bind(this);
	this.addFilter = this.addFilter.bind(this);
    }

    updateData() {
          var qfilter = buildQFilter(this.props.filters);
	  if (qfilter) {
		qfilter = '&qfilter=' + qfilter;
	  } else {
		qfilter = "";
	  }

          axios.get(config.API_URL + config.ES_BASE_PATH +
                    'field_stats&field=' + this.props.item +
		    '&from_date=' + this.props.from_date +
		    '&page_size=5' +
                    qfilter)
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
       if (prevProps.filters.length !==  this.props.filters.length) {
               this.updateData();
       }
    }

    addFilter(key, value, negated) {
        let activeFilters = [...this.props.filters, {label:"" + key + ": " + value, id: key, value: value, negated: negated}];
        this.props.UpdateFilter(activeFilters);
    }

    render() {
	    if (this.state.data && this.state.data.length) {
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
		 <EventValue field={this.props.item} value={item.key}
		             addFilter={this.addFilter}
			     right_info={<Badge>{item.doc_count}</Badge>}
		 />
		 </ListGroupItem>)
	    })}
	</ListGroup>
	</div>
        </div>
	</div>
	);
	    } else {
		return null;
	    }
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

export class RuleEditKebab extends React.Component {
    constructor(props) {
        super(props);
        this.displayToggle = this.displayToggle.bind(this);
        this.hideToggle = this.hideToggle.bind(this);
        this.state = { toggle: { show: false, action: "Disable" }};
    }

    displayToggle(action) {
        this.setState({toggle: {show: true, action: action}});
    }

    hideToggle() {
        this.setState({toggle: {show: false, action: this.state.toggle.action}});
    }

    render() {
        return(
            <React.Fragment>
                <DropdownKebab id="ruleActions" pullRight>
                        <MenuItem onClick={ e => {this.displayToggle("Enable") }}>
                        Enable Rule
                        </MenuItem>
                        <MenuItem  onClick={ e => {this.displayToggle("Disable") }}> 
                        Disable Rule
                        </MenuItem>
                </DropdownKebab>
                <RuleToggleModal show={this.state.toggle.show} action={this.state.toggle.action} config={this.props.config} close={this.hideToggle}/>
            </React.Fragment>
        )
    }
}

export class RuleToggleModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {rulesets: [], selected: [], supported_filters: [], comment: ""};
        this.submit = this.submit.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleCommentChange = this.handleCommentChange.bind(this);
        this.updateFilter = this.updateFilter.bind(this);
    }

    updateFilter() {
      if (this.props.filters && this.props.filters.length > 0) {
        var wanted_filters = Array.from(this.props.filters, x => x.id);
        var req_data = {fields: wanted_filters};
        axios.post(config.API_URL + config.PROCESSING_PATH + "test/", req_data).then( res => {
          var supp_filters = [];
          for(var i = 0; i < this.props.filters.length; i++) {
            if (res.data.fields.indexOf(this.props.filters[i].id) !== -1) {
                supp_filters.push(this.props.filters[i]);
            }
          }
          this.setState({supported_filters: supp_filters});
        });
      }
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
            if (prevProps.filters !== this.props.filters) {
                this.updateFilter();
            }
    }

    componentDidMount() {
	  if (this.state.rulesets.length === 0) {
             axios.get(config.API_URL + config.RULESET_PATH).then(res => {
               this.setState({rulesets: res.data['results']});
             })
	  }
        this.updateFilter();
    }

    submit() {
         this.state.selected.map(
             function(ruleset) {
                 var data = {ruleset: ruleset};
                 if (this.state.comment.length > 0) {
                     data['comment'] = this.state.comment
                 }
                 var url = config.API_URL + config.RULE_PATH + this.props.config.rule.sid;
                 if (this.props.action === "Enable") {
                     url = url + '/enable/';
                 } else {
                     url = url + '/disable/';
                 }
                 axios.post(url, data).then(
                     function(res) {
                         // Fixme notification or something
                         console.log("action on rule is a success");
                     }
                 );
                 return true;
             }
         , this); 
         this.props.close();
    }

    handleChange(event) {
        const target = event.target;
        const value = target.type === 'checkbox' ? target.checked : target.value;
        const name = target.name;
        console.log("check " + value + "for " + name);
        var sel_list = this.state.selected;
        if (value === false) {
             // pop element
             var index = sel_list.indexOf(name);
             if (index >= 0) {
                 sel_list.splice(index, 1);
                 this.setState({selected: sel_list});
             }
        } else {
            if (sel_list.indexOf(name) < 0) {
                 sel_list.push(name);
                 this.setState({selected: sel_list});
            }
        }
    }


    handleCommentChange(event) {
        this.setState({comment: event.target.value});
    }

    render() {
       return(
            <Modal show={this.props.show} onHide={this.props.close}>
    <Modal.Header>
      <button
        className="close"
        onClick={this.props.close}
        aria-hidden="true"
        aria-label="Close"
      >
        <Icon type="pf" name="close" />
      </button>
      {this.props.config.rule &&
        <Modal.Title>{this.props.action} Rule {this.props.config.rule.sid}</Modal.Title>
      }
      {!this.props.config.rule &&
	<Modal.Title>Add a {this.props.action} action</Modal.Title>
      }
    </Modal.Header>
    <Modal.Body>
       <Form horizontal>
       {this.state.supported_filters &&
	   this.state.supported_filters.map((item, index) => {
                  return (
		  <FormGroup key={item.id} controlId={item.id} disabled={false}>
			<Col sm={3}>
			<strong>{item.id}</strong>
			</Col>
			<Col sm={9}>
			<FormControl type={item.id} disabled={false} value={item.value} />
			</Col>
	          </FormGroup>
		  )
	       }
	       )
       }
        <FormGroup controlId="ruleset" disabled={false}>
            <Col sm={6}>
	      <label>Choose Ruleset(s)</label>
              {this.state.rulesets.map(function(ruleset) {
                      return(<div className="row"  key={ruleset.pk}>
                           <div className="col-sm-9">
                         <input type="checkbox" id={ruleset.pk} name={ruleset.pk} onChange={this.handleChange}/> <label>{ruleset.name}</label>
                         </div>
                      </div>);
                  }, this)
              }
	    </Col>
        </FormGroup>

        <div className="form-group">
            <div className="col-sm-9">
                <textarea value={this.state.comment} cols={70} onChange={this.handleCommentChange} />
            </div>
        </div>
      </Form>
    </Modal.Body>
    <Modal.Footer>
      <Button
        bsStyle="default"
        className="btn-cancel"
        onClick={this.props.close}
      >
        Cancel
      </Button>
      <Button bsStyle="primary" onClick={this.submit}>
        Submit
      </Button>
    </Modal.Footer>
  </Modal>
       )
    }
}

export function buildQFilter(filters) {
     var qfilter = [];
     for (var i=0; i < filters.length; i++) {
	var f_prefix = '';
	if (filters[i].negated) {
            f_prefix = 'NOT ';
	}
	if (filters[i].id === 'probe') {
            qfilter.push(f_prefix + 'host.raw:' + filters[i].value);
	    continue;
	} else if (filters[i].id === 'sprobe') {
            qfilter.push(f_prefix + 'host.raw:' + filters[i].value.id);
	    continue;
	}
	else if (filters[i].id === 'alert.signature_id') {
            qfilter.push(f_prefix + 'alert.signature_id:' + filters[i].value);
	    continue;
	}
	else if (filters[i].id === 'alert.tag') {
	    if (filters[i].value.id === 'untagged') {
		qfilter.push('NOT alert.tag:*');
	    } else {
            	qfilter.push(f_prefix + 'alert.tag:' + filters[i].value.id);
	    }
	    continue;
	}
	else if (filters[i].id === 'msg') {
            qfilter.push(f_prefix + 'alert.signature:' + filters[i].value);
	    continue;
	}
	else if (typeof filters[i].value === 'string') {
            qfilter.push(f_prefix + filters[i].id + ':"' + encodeURIComponent(filters[i].value) + '"');
	    continue;
	}
	else {
            qfilter.push(f_prefix + filters[i].id + ':' + filters[i].value);
	    continue;
	}
     }
     if (qfilter.length === 0) {
	 return null;
     }
     return qfilter.join(" AND ");
}

export class RulesList extends HuntList {
  constructor(props) {
    super(props);

    var only_hits = localStorage.getItem("rules_list.only_hits");
    if (!only_hits) {
        only_hits = false;
    }

    this.state = {
      rules: [], sources: [], rules_count: 0,
      loading: true,
      refresh_data: false,
      view: 'rules_list',
      display_toggle: true,
      only_hits: only_hits,
      action: { view: false, type: 'suppress'},
      net_error: undefined
    };
    this.updateRulesState = this.updateRulesState.bind(this);
    this.fetchHitsStats = this.fetchHitsStats.bind(this);
    this.displayRule = this.displayRule.bind(this);
    this.RuleUpdateFilter = this.RuleUpdateFilter.bind(this);
    this.actionsButtons = this.actionsButtons.bind(this);
    this.createSuppress = this.createSuppress.bind(this);
    this.createThreshold = this.createThreshold.bind(this);
    this.createTag = this.createTag.bind(this);
    this.closeAction = this.closeAction.bind(this);
    this.toggleOnlyHits = this.toggleOnlyHits.bind(this);
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
     if (prevProps.from_date !==  this.props.from_date) {
             this.fetchHitsStats(this.state.rules);
     }
  }

   buildFilter(filters) {
     var l_filters = {};
     for (var i=0; i < filters.length; i++) {
	if (filters[i].id !== 'probe' && filters[i].id !== 'alert.tag') {
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
     var qfilter = buildQFilter(filters);
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
	 var qfilter = buildQFilter(this.props.filters);
     updateHitsStats(rules, this.props.from_date, this.updateRulesState, qfilter);
  }

  displayRule(rule) {
      this.setState({display_rule: rule});
      let activeFilters = [...this.props.filters, {label:"Signature ID: " + rule.sid, id: 'alert.signature_id', value: rule.sid}];
      this.RuleUpdateFilter(activeFilters);
  }

  fetchData(rules_stat, filters) {
     var string_filters = this.buildFilter(filters);

     this.setState({refresh_data: true});
     axios.all([
          axios.get(config.API_URL + config.RULE_PATH + "?" + this.buildListUrlParams(rules_stat) + "&from_date=" + this.props.from_date + string_filters),
          axios.get(config.API_URL + config.SOURCE_PATH + "?page_size=100"),
	  ])
      .then(axios.spread((RuleRes, SrcRes) => {
	 var sources_array = SrcRes.data['results'];
	 var sources = {};
	 this.setState({net_error: undefined});
	 for (var i = 0; i < sources_array.length; i++) {
	     var src = sources_array[i];
	     sources[src.pk] = src;
	 }
         this.setState({ rules_count: RuleRes.data['count'], rules: RuleRes.data['results'], sources: sources, loading: false, refresh_data: false});
	 if (!RuleRes.data.results[0].timeline_data) {
	     this.fetchHitsStats(RuleRes.data['results']);
	 } else {
             this.buildHitsStats(RuleRes.data['results']);
	 }
     })).catch( e => {
         this.setState({net_error: e, loading: false});
     });
  }

  componentDidMount() {
      var sid = this.findSID(this.props.filters);
      if (sid !== undefined) {
          this.setState({display_rule: sid, view: 'rule', display_toggle: false, loading: false});
      } else {
          this.fetchData(this.props.config, this.props.filters);
      }
  }

  findSID(filters) {
	var found_sid = undefined;
	for (var i = 0; i < filters.length; i++) {
	    if (filters[i].id === 'alert.signature_id') {
		found_sid = filters[i].value;
		break;
	    }
	}
	return found_sid;
  }

  RuleUpdateFilter(filters) {
        // iterate on filter, if we have a sid we display the rule page
	var found_sid = this.findSID(filters);
	if (found_sid !== undefined) {
		this.setState({view: 'rule', display_toggle: false});
	} else {
		this.setState({view: 'rules_list', display_toggle: true});
	}
  	this.UpdateFilter(filters);
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

  closeAction() {
        this.setState({action: {view: false, type: 'suppress'}});
  }

  toggleOnlyHits() {
	localStorage.setItem("rules_list.only_hits", !this.state.only_hits);
	this.setState({only_hits: !this.state.only_hits});
  }

  actionsButtons() {
      return(<React.Fragment>
             <div className="form-group">
                 <label>
		     <input type="checkbox"
		            name="only_hits"
			    checked={this.state.only_hits}
			    onChange={this.toggleOnlyHits}
	             /> Only hits</label>
             </div>
	     <div className="form-group">
	         <DropdownButton bsStyle="default" title="Actions" key="actions" id="dropdown-basic-actions">
		 <MenuItem eventKey="1" onClick={e => { this.createSuppress(); }}>Suppress</MenuItem>
		 <MenuItem eventKey="2" onClick={e => { this.createThreshold(); }}>Threshold</MenuItem>
		 <MenuItem divider />
		 <MenuItem eventKey="3" onClick={e => { this.createTag(); }}>Tag</MenuItem>
	         </DropdownButton>
	     </div>
	     </React.Fragment>
       );
  }
  
  render() {
    return (
        <div className="RulesList">
	<Spinner loading={this.state.loading} >
	    {this.state.net_error !== undefined &&
	         <div className="alert alert-danger">Problem with backend: {this.state.net_error.message}</div>	
	    }
	    <HuntFilter ActiveFilters={this.props.filters}
	          config={this.props.config}
		  ActiveSort={this.props.config.sort}
		  UpdateFilter={this.RuleUpdateFilter}
		  UpdateSort={this.UpdateSort}
		  setViewType={this.setViewType}
		  filterFields={RuleFilterFields}
		  sort_config={RuleSortFields}
		  displayToggle={this.state.display_toggle}
		  actionsButtons={this.actionsButtons}
            />
	    {this.state.view === 'rules_list' &&
            this.props.config.view_type === 'list' &&
	    <ListView>
            {this.state.rules.map(function(rule) {
                return(
                   <RuleInList key={rule.sid} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.displayRule} />
                )
             },this)}
	    </ListView>
            }
            {this.state.view === 'rules_list' &&
	     this.props.config.view_type === 'card' &&
                <div className='container-fluid container-cards-pf'>
                <div className='row row-cards-pf'>
                {this.state.rules.map(function(rule) {
			 if ((!this.state.only_hits) || (rule.hits > 0)) {
                         return(
                                <RuleCard key={rule.pk} data={rule} state={this.state} from_date={this.props.from_date} SwitchPage={this.displayRule} />
                         )
			 }
			 return(null);
             },this)}
                </div>
                </div>
            }
            {this.state.view === 'rules_list' &&
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
	    }
            {this.state.view === 'rule' &&
	        <RulePage rule={this.state.display_rule} config={this.props.config} filters={this.props.filters} from_date={this.props.from_date} UpdateFilter={this.RuleUpdateFilter}/>
	    }
            {this.state.view === 'dashboard' &&
	        <HuntDashboard />
	    }

	    </Spinner>
	       <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.config}  filters={this.props.filters} close={this.closeAction} />
        </div>
    );
  }
}
