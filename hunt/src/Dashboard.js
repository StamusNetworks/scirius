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
import axios from 'axios';
//import { SciriusChart } from './Chart.js';
import { DonutChart } from 'patternfly-react';
//import { ListGroup, ListGroupItem, Badge } from 'react-bootstrap';
//import { EventValue } from './Event.js';
import { HuntStat, buildQFilter, RuleToggleModal } from './Rule.js';
import { HuntList } from './Api.js';
import { HuntFilter } from './Filter.js';
import * as config from './config/Api.js';
import { SciriusChart } from './Chart.js';

export class HuntDashboard extends HuntList {
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
      net_error: undefined,
      rules_filters: [],
      supported_actions: []
    };
  }

    componentDidMount() {
      axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
      	res => {
		var fdata = [];
		for (var i in res.data) {
			if (['filter', 'hunt'].indexOf(res.data[i].queryType) !== -1) {
				fdata.push(res.data[i]);
			}
		}
		this.setState({rules_filters: fdata});
	});
      this.loadActions();
    }

    render() {
        return(
	    <div>
	    	  <HuntFilter ActiveFilters={this.props.filters}
    	          config={this.props.config}
    		  ActiveSort={this.props.config.sort}
    		  UpdateFilter={this.UpdateFilter}
    		  UpdateSort={this.UpdateSort}
    		  setViewType={this.setViewType}
    		  filterFields={this.state.rules_filters}
    		  sort_config={undefined}
    		  displayToggle={undefined}
		  actionsButtons={this.actionsButtons}
		  queryType={['filter']}
                />

	       <div className="container-fluid container-cards-pf">
	          <div className="row">
		      <div className="col-md-10">
		         <HuntTimeline from_date={this.props.from_date} filters={this.props.filters} />
	              </div>
		      <div className="col-md-2">
                         <HuntTrend from_date={this.props.from_date} filters={this.props.filters} />
	              </div>
		  </div>
 	          <div className="row row-cards-pf">
		    <h4>Basic information</h4>
                    <HuntStat title="Signatures" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.signature' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={4} addFilter={this.addFilter}/>
                    <HuntStat title="Categories" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.category' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Severities" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.severity' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
                    <HuntStat title="Probes" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='host' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
		  </div>
	          <div className="row row-cards-pf">
		    <h4>Organizational information</h4>
                    <HuntStat title="Sources" config={this.props.config} filters={this.props.filters}  item='alert.source.ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Targets" config={this.props.config}  filters={this.props.filters}  item='alert.target.ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Lateral" config={this.props.config}  filters={this.props.filters}  item='alert.lateral' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
		  </div>
	          <div className="row row-cards-pf">
		    <h4>Metadata information</h4>
                    <HuntStat title="Signature severity" config={this.props.config} filters={this.props.filters}  item='alert.metadata.signature_severity' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Attack target" config={this.props.config} filters={this.props.filters}  item='alert.metadata.attack_target' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Affected product" config={this.props.config} filters={this.props.filters}  item='alert.metadata.affected_product' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Malware family" config={this.props.config} filters={this.props.filters}  item='alert.metadata.malware_family' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
		  </div>
 	          <div className="row row-cards-pf">
		    <h4>IP information</h4>
                    <HuntStat title="Sources IP" rule={this.state.rule} config={this.props.config} filters={this.props.filters}  item='src_ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Destinations IP" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='dest_ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Source Ports" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='src_port' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
                    <HuntStat title="Destinations Ports" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='dest_port' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
                    <HuntStat title="IP Protocols" rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='proto' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
		  </div>
                <div className='row row-cards-pf'>
		    <h4>HTTP information</h4>
                    <HuntStat title="Hostname" config={this.props.config} filters={this.props.filters}  item='http.hostname' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="URL" config={this.props.config} filters={this.props.filters}  item='http.url' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="User agent" config={this.props.config} filters={this.props.filters}  item='http.http_user_agent' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                    <HuntStat title="Status" config={this.props.config} filters={this.props.filters}  item='http.status' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>DNS information</h4>
                    <HuntStat title="Name" config={this.props.config} filters={this.props.filters} item='dns.query.rrname' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter}/>
                    <HuntStat title="Type" config={this.props.config} filters={this.props.filters}  item='dns.query.rrtype' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>TLS information</h4>
                    <HuntStat title="SNI" config={this.props.config} filters={this.props.filters} item='tls.sni' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter}/>
                    <HuntStat title="Subject DN" config={this.props.config} filters={this.props.filters} item='tls.subject' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter}/>
                    <HuntStat title="Issuer DN" config={this.props.config} filters={this.props.filters} item='tls.issuerdn' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} />
                    <HuntStat title="Fingerprint" config={this.props.config} filters={this.props.filters}  item='tls.fingerprint' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}/>
                </div>
	      </div>	  
	       <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.config}  filters={this.props.filters} close={this.closeAction} />
	    </div>
	    );
    }
}


class HuntTrend extends React.Component {
    constructor(props) {
        super(props);
	this.state = {data: undefined};
	this.fetchData = this.fetchData.bind(this);
    }

    fetchData() {
        var string_filters = "";
        var qfilter = buildQFilter(this.props.filters);
        if (qfilter) {
   	        string_filters += '&filter=' +  qfilter;
        }
	    axios.get(config.API_URL + config.ES_BASE_PATH +
                    'alerts_count&prev=1&hosts=*&from_date=' + this.props.from_date
                    + string_filters)
             .then(res => {
                  if (typeof(res.data) !== 'string') {
               	      this.setState({ data: res.data });
	          }
            })
    }

    componentDidMount() {
	    this.fetchData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if ((prevProps.from_date !==  this.props.from_date) || (prevProps.filters !== this.props.filters)) {
           this.fetchData();
       }
    }

    render() {
        var g_data = undefined;
	if (this.state.data) {
		g_data = {
	            columns: [
	            ["previous", this.state.data.prev_doc_count],
	            ["current", this.state.data.doc_count]
	            ],
	            groups: [
	              ["previous", "current"]
	            ]
	        };	
	} else {
		g_data = {
	            columns: [
	            ["previous", 0],
	            ["current", 0]
	            ],
	            groups: [
	              ["previous", "current"]
	            ]
	        };
	}
        return(
		<div>
		      <DonutChart
		          data={g_data}
                          title={{type: "percent" }}
		      />
		</div>
	);
    }
}

class HuntTimeline extends React.Component {
    constructor(props) {
        super(props);
	this.state = {data: undefined};
	this.fetchData = this.fetchData.bind(this);
    }

    fetchData() {
        var string_filters = "";
        var key = undefined;
        var qfilter = buildQFilter(this.props.filters);
        if (qfilter) {
   	        string_filters += '&filter=' +  qfilter;
        }
	    axios.get(config.API_URL + config.ES_BASE_PATH +
                    'timeline&hosts=*&from_date=' + this.props.from_date + string_filters)
             .then(res => {
            /* iterate on actual row: build x array, for each row build hash x -> value */
            /* sort x array */
            /* for key in x array, build each row, value if exists, 0 if not */
         var prows = {x: []};
	     for (key in res.data) {
		     if (!(['interval', 'from_date'].includes(key))) {
			    prows[key] = {};
			    for (var entry in res.data[key].entries) {
                    if (prows['x'].indexOf(res.data[key].entries[entry].time) === -1) {
                        prows['x'].push(res.data[key].entries[entry].time);
                    }
                    prows[key][res.data[key].entries[entry].time] = res.data[key].entries[entry].count;
			    }
		     }
	     }

         var pprows = prows['x'].slice();
         pprows.sort(function(a, b){return a - b});
         var putindrows = [''];
         putindrows[0] = pprows;
         putindrows[0].unshift('x');
         for (key in prows) {
            if (key === 'x') {
                    continue;
            }
            var pvalue = [key];
            for (var i=1; i < putindrows[0].length; i++) {
                if (putindrows[0][i] in prows[key]) {
                    pvalue.push(prows[key][putindrows[0][i]]);
                } else {
                    pvalue.push(0);
                }
            }
            putindrows.push(pvalue);
         }
         this.setState({data: {x: 'x', columns: putindrows }});
       })
    }

    componentDidMount() {
	    this.fetchData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if ((prevProps.from_date !==  this.props.from_date) || (prevProps.filters !== this.props.filters)) {
           this.fetchData();
       }
    }

    render() {
    return(
	     <div>
		   {this.state.data &&
      <SciriusChart data={ this.state.data }
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            tick: { fit: true, format: '%Y-%m-%d %H:%M'},
                            show: true
                     },
                     y: { show: true }
               }}
               legend = {{
                  show: true    
               }}
               size = {{ height: 190 }}
               point = {{ show: false }}
               from_date = {this.props.from_date}
      />
		   }
              </div>
        );
    }
}
