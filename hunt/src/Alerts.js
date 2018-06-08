import React from 'react';
import { HuntList } from './Api.js';
import { buildQFilter } from './Rule.js';
import { HuntFilter } from './Filter.js';
import * as config from './config/Api.js';

import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
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
          this.setState({alerts: res.data, loading: false});
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
                      <AlertInList key={rule._id} id={rule._id} data={rule._source}  from_date={this.props.from_date} />
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
    render() {
        var data = this.props.data;
        var ip_params = data.src_ip + ':' + data.src_port +' -> ' + data.dest_ip + ':' + data.dest_port;
        return(
           <ListViewItem
            id={this.props.id}
            leftContent={<ListViewIcon type="pf" name="security" />}
            heading={data.alert.signature}
            description={ip_params}
	    additionalInfo={[
	    		     <ListViewInfoItem key="timestamp"><p>{data.timestamp}</p></ListViewInfoItem>,
	    		     <ListViewInfoItem key="app_proto"><p>Proto: {data.app_proto}</p></ListViewInfoItem>,
	                     <ListViewInfoItem key="host"><p>Probe: {data.host}</p></ListViewInfoItem>,
	                     <ListViewInfoItem key="category"><p>Category: {data.alert.category}</p></ListViewInfoItem>,
	                    ]}
	   >
	      <Row>
		    {data.alert.target !== undefined &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <dt>Target IP</dt><dd>{data.alert.target.ip}</dd>
			   <dt>Target Network</dt><dd>{data.alert.target.net_info.join(', ')}</dd>
			   <dt>Source IP</dt><dd>{data.alert.source.ip}</dd>
			   <dt>Source Network</dt><dd>{data.alert.source.net_info.join(', ')}</dd>
			</dl>
		 </Col>
		    }
		    {data.app_proto === "http" &&
	         <Col sm={4}>
		        <dl className="dl-horizontal">
			   <dt>Host</dt><dd>{data.http.hostname}</dd>
			   <dt>URL</dt><dd>{data.http.url}</dd>
			   <dt>Method</dt><dd>{data.http.http_method}</dd>
			   <dt>User Agent</dt><dd>{data.http.http_user_agent}</dd>
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
                                  <dt>{field[0]}</dt><dd>{field[1].join(', ')}</dd>
			      </React.Fragment>
			  )
		      })
		      }
		      </dl>
		 </Col>
		    }
              </Row>
           </ListViewItem>
    )
    }
}
