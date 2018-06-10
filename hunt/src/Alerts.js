import React from 'react';
import { HuntList } from './Api.js';
import { buildQFilter } from './Rule.js';
import { HuntFilter } from './Filter.js';
import { EventField } from './Event.js';
import * as config from './config/Api.js';

import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner, Icon } from 'patternfly-react';
import axios from 'axios';

export const AlertFilterFields = [
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
    id: 'sid',
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

export const AlertSortFields = [
  {
    id: 'timestamp',
    title: 'timestamp',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'msg',
    title: 'Message',
    isNumeric: false,
    defaultAsc: true,
  }
];


export class AlertsList extends HuntList {
  constructor(props) {
    super(props);
    this.state = {
      alerts: [],
      loading: true,
      refresh_data: false,
    };
   this.fetchData = this.fetchData.bind(this);
  }

  fetchData(state, filters) {
     var string_filters = buildQFilter(filters);
     this.setState({refresh_data: true});
     var url = config.API_URL + config.ES_BASE_PATH + 'alerts_tail&search_target=0&' + this.buildListUrlParams(state) + "&from_date=" + this.props.from_date + '&filter=' + string_filters;
     axios.get(url).then( res => {
	  if ((res.data !== null) && (typeof res.data !== 'string')) {
              this.setState({alerts: res.data, loading: false});
	  } else {
              this.setState({loading: false});
	  }
     }
     )
  }

  render() {
    return (
       <div className="AlertsList">
	    <HuntFilter ActiveFilters={this.props.filters}
	          config={this.props.config}
		  ActiveSort={this.props.config.sort}
		  UpdateFilter={this.UpdateFilter}
		  UpdateSort={this.UpdateSort}
		  setViewType={this.setViewType}
		  filterFields={AlertFilterFields}
		  sort_config={AlertSortFields}
		  displayToggle={this.state.display_toggle}
            />
         <Spinner loading={this.state.loading}>
           <ListView>
           {this.state.alerts.map(rule => {
                  return(
                      <AlertInList key={rule._id} id={rule._id} data={rule._source}  from_date={this.props.from_date} UpdateFilter={this.UpdateFilter} filters={this.props.filters} />
                  )
              })
           }
           </ListView>
	 </Spinner>  
       </div>
    )
  }
}

class AlertInList extends React.Component {
    constructor(props) {
       super(props);
       this.addFilter = this.addFilter.bind(this);
    }

    addFilter(key, value, negated) {
        let activeFilters = [...this.props.filters,
	                     {label:"" + key + ": " + value, id: key, value: value, negated: negated}];
        this.props.UpdateFilter(activeFilters);
    }

    render() {
        var data = this.props.data;
        var ip_params = data.src_ip + ':' + data.src_port +' -> ' + data.dest_ip + ':' + data.dest_port;
        return(
           <ListViewItem
            id={this.props.id}
            leftContent={<ListViewIcon type="pf" name="security" />}
            heading={<span data-toggle="tooltip" title={data.alert.signature}>{data.alert.signature}</span>}
            description={ip_params}
	    additionalInfo={[
	    		     <ListViewInfoItem key="timestamp"><p>{data.timestamp}</p></ListViewInfoItem>,
	    		     <ListViewInfoItem key="app_proto"><p>Proto: {data.app_proto}</p></ListViewInfoItem>,
	                     <ListViewInfoItem key="host"><p>Probe: {data.host}</p></ListViewInfoItem>,
	                     <ListViewInfoItem key="category"><p>Category: {data.alert.category}</p></ListViewInfoItem>,
	                    ]}
	   >
	      <Row>
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="Source IP" field="src_ip" value={data.src_ip} addFilter={this.addFilter} />
			   <EventField field_name="Source port" field="src_port" value={data.src_port} addFilter={this.addFilter} />
			   <EventField field_name="Destination IP" field="dest_ip" value={data.dest_ip} addFilter={this.addFilter} />
			   <EventField field_name="Destination port" field="dest_port" value={data.dest_port} addFilter={this.addFilter} />
			</dl>
		 </Col>

		    {data.alert.target !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="Target IP" field="alert.target.ip" value={data.alert.target.ip} addFilter={this.addFilter} />
			   <EventField field_name="Target port" field="alert.target.port" value={data.alert.target.port} addFilter={this.addFilter} />
			   <dt>Target Network</dt><dd>{data.alert.target.net_info.join(', ')}</dd>
			   <EventField field_name="Source IP" field="alert.source.ip" value={data.alert.source.ip} addFilter={this.addFilter} />
			   <EventField field_name="Source port" field="alert.source.port" value={data.alert.source.port} addFilter={this.addFilter} />
			   <dt>Source Network</dt><dd>{data.alert.source.net_info.join(', ')}</dd>
			</dl>
		 </Col>
		    }
		    {data.http !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="Host" field="http.hostname" value={data.http.hostname} addFilter={this.addFilter} />
			   <EventField field_name="URL" field="http.url" value={data.http.url} addFilter={this.addFilter} />
			   <EventField field_name="Status" field="http.status" value={data.http.status} addFilter={this.addFilter} />
			   <EventField field_name="Method" field="http.http_method" value={data.http.http_method} addFilter={this.addFilter} />
			   <EventField field_name="User Agent" field="http.http_user_agent" value={data.http.http_user_agent} addFilter={this.addFilter} />
			   {data.http.http_refer !== undefined &&
			      <EventField field_name="Referrer" field="http.http_refer" value={data.http.http_refer} addFilter={this.addFilter} />
			   }
			</dl>
		 </Col>
		    }
		    {data.alert.metadata &&
	         <Col sm={4}>
		      <dl className="dl-horizontal">
		      {   
			  Object.entries(data.alert.metadata).map( field => {
			  return(
			      <React.Fragment key={field[0]} >
                                  <EventField field_name={field[0]} field={'alert.metadata.' + field[0]} value={field[1].join(', ')} addFilter={this.addFilter} />
			      </React.Fragment>
			  )
		      })
		      }
		      </dl>
		 </Col>
		    }
              </Row>
	      {data.http &&
	      <Row>
	         { data.http.http_request_body_printable &&
	         <Col sm={6}>
		      <strong>HTTP request body</strong>
		      <pre>{data.http.http_request_body_printable}</pre>
		 </Col>
	         }
	         {data.http.http_response_body_printable &&
	         <Col sm={6}>
		      <strong>HTTP response body</strong>
		      <pre>{data.http.http_response_body_printable}</pre>
		 </Col>
	         }
              </Row>
	      }
           </ListViewItem>
    )
    }
}


