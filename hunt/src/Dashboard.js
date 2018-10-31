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
import DropdownKebab from "patternfly-react/dist/esm/components/DropdownKebab/DropdownKebab";
import MenuItem from "react-bootstrap/es/MenuItem";
import Modal from "patternfly-react/dist/esm/components/Modal/Modal";
import ListGroup from "react-bootstrap/es/ListGroup";
import ListGroupItem from "react-bootstrap/es/ListGroupItem";
import {EventValue} from "./Event";
import Badge from "react-bootstrap/es/Badge";

export class HuntDashboard extends HuntList {
  constructor(props) {
    super(props);

    var only_hits = localStorage.getItem("rules_list.only_hits");
    if (!only_hits) {
        only_hits = false;
    }

    this.state = {
      rules: [], sources: [], rulesets: [], rules_count: 0,
      loading: true,
      refresh_data: false,
      view: 'rules_list',
      display_toggle: true,
      only_hits: only_hits,
      action: { view: false, type: 'suppress'},
      net_error: undefined,
      rules_filters: [],
      supported_actions: [],
      moreModal: null,
      moreResults: [],
    };
  }

    componentDidMount() {
       if (this.state.rulesets.length === 0) {
             axios.get(config.API_URL + config.RULESET_PATH).then(res => {
               this.setState({rulesets: res.data['results']});
             })
       }
      axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
      	res => {
		var fdata = [];
		for (var i in res.data) {
			/* Only ES filter are allowed for Alert page */
			if (['filter'].indexOf(res.data[i].queryType) !== -1) {
				if (res.data[i].filterType !== 'hunt') {
					fdata.push(res.data[i]);
				}
			}
		}
		this.setState({rules_filters: fdata});
	}
  	);
      this.loadActions();
    }
    loadMore = (item, url) => {
        axios.get(url)
            .then(json => {
                this.setState({ ...this.state, moreModal: item, moreResults: json.data});
            });
    }
    hideMoreModal = () => this.setState({...this.state, moreModal: null });
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
		  queryType={['filter', 'rest']}
                />

	       <div className="container-fluid container-cards-pf">
	          <div className="row">
		      <div className="col-md-10">
		         <HuntTimeline system_settings={this.props.system_settings} from_date={this.props.from_date} filters={this.props.filters} />
	              </div>
		      <div className="col-md-2">
                         <HuntTrend system_settings={this.props.system_settings} from_date={this.props.from_date} filters={this.props.filters} />
	              </div>
		  </div>
 	          <div className="row row-cards-pf">
		    <h4>Basic information</h4>
                    <HuntStat title="Signatures" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.signature' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={4} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Categories" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.category' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Severities" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='alert.severity' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Probes" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='host' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
		  </div>
	          <div className="row row-cards-pf">
		    <h4>Organizational information</h4>
                    <HuntStat title="Sources" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='alert.source.ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Targets" system_settings={this.props.system_settings} config={this.props.config}  filters={this.props.filters}  item='alert.target.ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Lateral" system_settings={this.props.system_settings} config={this.props.config}  filters={this.props.filters}  item='alert.lateral' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
		  </div>
	          <div className="row row-cards-pf">
		    <h4>Metadata information</h4>
                    <HuntStat title="Signature severity" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='alert.metadata.signature_severity' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Attack target" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='alert.metadata.attack_target' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Affected product" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='alert.metadata.affected_product' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Malware family" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='alert.metadata.malware_family' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
		  </div>
 	          <div className="row row-cards-pf">
		    <h4>IP information</h4>
                    <HuntStat title="Sources IP" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config} filters={this.props.filters}  item='src_ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Destinations IP" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='dest_ip' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Source Ports" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='src_port' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Destinations Ports" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='dest_port' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="IP Protocols" system_settings={this.props.system_settings} rule={this.state.rule} config={this.props.config}  filters={this.props.filters}  item='proto' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
		  </div>
                <div className='row row-cards-pf'>
		    <h4>HTTP information</h4>
                    <HuntStat title="Hostname" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='http.hostname' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="URL" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='http.url' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="User agent" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='http.http_user_agent' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Status" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='http.status' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>DNS information</h4>
                    <HuntStat title="Name" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='dns.query.rrname' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Type" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='dns.query.rrtype' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} col={2} addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>TLS information</h4>
                    <HuntStat title="Server Name Indication" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='tls.sni' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Subject DN" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='tls.subject' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Issuer DN" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='tls.issuerdn' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter} addFilter={this.addFilter}  loadMore={this.loadMore}/>
                    <HuntStat title="Fingerprint" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='tls.fingerprint' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="JA3 Hash" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='tls.ja3.hash' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>SMTP information</h4>
                    <HuntStat title="Mail From" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smtp.mail_from' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="RCPT To" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smtp.rcpt_to' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Helo" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smtp.helo' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>SMB information</h4>
                    <HuntStat title="Command" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smb.command' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Status" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smb.status' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Filename" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smb.filename' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Share" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='smb.share' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>
                <div className='row row-cards-pf'>
		    <h4>SSH information</h4>
                    <HuntStat title="Client Software" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters} item='ssh.client.software_version' from_date={this.props.from_date}  UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                    <HuntStat title="Server Software" system_settings={this.props.system_settings} config={this.props.config} filters={this.props.filters}  item='ssh.server.software_version' from_date={this.props.from_date} UpdateFilter={this.UpdateFilter}  addFilter={this.addFilter} loadMore={this.loadMore}/>
                </div>

	      </div>	  
	       <RuleToggleModal show={this.state.action.view} action={this.state.action.type} config={this.props.config}  filters={this.props.filters} close={this.closeAction} rulesets={this.state.rulesets} />
                <Modal show={!(this.state.moreModal===null)} onHide={() => { this.hideMoreModal() }}>

                    <Modal.Header>More results <Modal.CloseButton closeText={"Close"} onClick={() => { this.hideMoreModal() }}/> </Modal.Header>
                    <Modal.Body>
                        <div className="hunt-stat-body">
                            <ListGroup>
                                {this.state.moreResults.map(item => {
                                    return (<ListGroupItem key={item.key}>
                                        <EventValue field={this.state.moreModal} value={item.key}
                                                    addFilter={this.addFilter}
                                                    right_info={<Badge>{item.doc_count}</Badge>}
                                        />
                                    </ListGroupItem>)
                                })}
                            </ListGroup>
                        </div>
                    </Modal.Body>
                </Modal>
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
        var qfilter = buildQFilter(this.props.filters, this.props.system_settings);
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
                  title={{type: "max" }}
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
        var qfilter = buildQFilter(this.props.filters, this.props.system_settings);
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
         if (putindrows.length === 1) {
                putindrows = [];
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
                            tick: { fit: false, format: '%Y-%m-%d %H:%M'},
                            show: true
                     },
                     y: { show: true }
               }}
               legend = {{
                  show: true    
               }}
               size = {{ height: 190 }}
               point = {{ show: true }}
      />
		   }
              </div>
        );
    }
}
