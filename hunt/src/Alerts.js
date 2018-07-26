import React from 'react';
import { HuntList } from './Api.js';
import { buildQFilter } from './Rule.js';
import { HuntFilter } from './Filter.js';
import { EventField } from './Event.js';
import * as config from './config/Api.js';
import ReactJson from 'react-json-view';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import axios from 'axios';

export const AlertSortFields = [
  {
    id: 'timestamp',
    title: 'Timestamp',
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
      rules_filters: []
    };
   this.fetchData = this.fetchData.bind(this);
  }


  componentDidMount() {
	this.fetchData(this.props.config, this.props.filters);
      axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(
      	res => {
		this.setState({rules_filters: res.data});
	}
  	);
  }
  
  fetchData(state, filters) {
     var string_filters = buildQFilter(filters);
     if (string_filters === null) {
        string_filters = "";
     } else {
        string_filters = "&filter=" + string_filters;
     }
     this.setState({refresh_data: true});
     var url = config.API_URL + config.ES_BASE_PATH + 'alerts_tail&search_target=0&' + this.buildListUrlParams(state) + "&from_date=" + this.props.from_date + string_filters;
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
		  filterFields={this.state.rules_filters}
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
        var ip_params = data.src_ip + ' -> ' + data.dest_ip;
        return(
           <ListViewItem
            id={this.props.id}
            leftContent={<ListViewIcon type="pf" name="security" />}
            description={<span data-toggle="tooltip" title={data.alert.signature}>{data.alert.signature}</span>}
            heading={ip_params}
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
			   <EventField field_name="Signature" field="alert.signature" value={data.alert.signature} addFilter={this.addFilter} />
			   <EventField field_name="SID" field="alert.signature_id" value={data.alert.signature_id} addFilter={this.addFilter} />
			   <EventField field_name="Category" field="alert.category" value={data.alert.category} addFilter={this.addFilter} />
			   <EventField field_name="Severity" field="alert.severity" value={data.alert.severity} addFilter={this.addFilter} />
			   <EventField field_name="Revision" field="alert.rev" value={data.alert.rev} addFilter={this.addFilter} />
			</dl>
		 </Col>

	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="Source IP" field="src_ip" value={data.src_ip} addFilter={this.addFilter} />
			   <EventField field_name="Source port" field="src_port" value={data.src_port} addFilter={this.addFilter} />
			   <EventField field_name="Destination IP" field="dest_ip" value={data.dest_ip} addFilter={this.addFilter} />
			   <EventField field_name="Destination port" field="dest_port" value={data.dest_port} addFilter={this.addFilter} />
			   {data.app_proto &&
			   <EventField field_name="Application protocol" field="app_proto" value={data.app_proto} addFilter={this.addFilter} />
			   }
			   <EventField field_name="Probe" field="probe" value={data.host} addFilter={this.addFilter} />
			</dl>
		 </Col>

		    {data.alert.target !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <dt>Source Network</dt><dd>{data.alert.source.net_info.join(', ')}</dd>
			   <EventField field_name="Source IP" field="alert.source.ip" value={data.alert.source.ip} addFilter={this.addFilter} />
			   <EventField field_name="Source port" field="alert.source.port" value={data.alert.source.port} addFilter={this.addFilter} />
			   <dt>Target Network</dt><dd>{data.alert.target.net_info.join(', ')}</dd>
			   <EventField field_name="Target IP" field="alert.target.ip" value={data.alert.target.ip} addFilter={this.addFilter} />
			   <EventField field_name="Target port" field="alert.target.port" value={data.alert.target.port} addFilter={this.addFilter} />
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
		    {data.tls !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="TLS Subject" field="tls.subject" value={data.tls.subject} addFilter={this.addFilter} />
			   <EventField field_name="TLS Issuer" field="tls.issuerdn" value={data.tls.issuerdn} addFilter={this.addFilter} />
			   <EventField field_name="TLS SNI" field="tls.sni" value={data.tls.sni} addFilter={this.addFilter} />
			   <EventField field_name="TLS not before" field="tls.notbefore" value={data.tls.notbefore} addFilter={this.addFilter} />
			   <EventField field_name="TLS not after" field="tls.notafter" value={data.tls.notafter} addFilter={this.addFilter} />
			</dl>
		 </Col>
		    }
		    {data.flow !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <EventField field_name="Flow start" field="flow.start" value={data.flow.start} addFilter={this.addFilter} />
			   <EventField field_name="Pkts to server" field="flow.pkts_toserver" value={data.flow.pkts_toserver} addFilter={this.addFilter} />
			   <EventField field_name="Bytes to server" field="flow.bytes_toserver" value={data.flow.bytes_toserver} addFilter={this.addFilter} />
			   <EventField field_name="Pkts to client" field="flow.pkts_toclient" value={data.flow.pkts_toclient} addFilter={this.addFilter} />
			   <EventField field_name="Bytes to client" field="flow.bytes_toclient" value={data.flow.bytes_toclient} addFilter={this.addFilter} />
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
		      <pre style={{"maxHeight": "12pc"}} >{data.http.http_request_body_printable}</pre>
		 </Col>
	         }
	         {data.http.http_response_body_printable &&
	         <Col sm={6}>
		      <strong>HTTP response body</strong>
		      <pre style={{"maxHeight": "12pc"}} >{data.http.http_response_body_printable}</pre>
		 </Col>
	         }
              </Row>
	      }
	      <Row>
	        <Col sm={12}>
		   <strong>Full JSON event</strong>
		   <ReactJson
		       name={false}
		       src={data}
		       displayDataTypes = {false}
		       displayObjectSize = {false}
		       collapseStringsAfterLength = {150}
		       collapsed = {true}
		    />
		</Col>
	      </Row>
           </ListViewItem>
    )
    }
}


