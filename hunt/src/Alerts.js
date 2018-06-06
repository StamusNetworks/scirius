import React from 'react';
import { HuntList, HuntPaginationRow } from './Api.js';
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
       <h1>Alerts list</h1>
	    <HuntFilter ActiveFilters={this.props.filters}
	          config={this.props.config}
		  ActiveSort={this.props.config.sort}
		  UpdateFilter={this.RuleUpdateFilter}
		  UpdateSort={this.UpdateSort}
		  setViewType={this.setViewType}
		  filterFields={AlertFilterFields}
		  sort_config={AlertSortFields}
		  displayToggle={this.state.display_toggle}
            />
           <ListView>
           {this.state.alerts.map(rule => {
                  return(
                      <AlertInList key={rule._id} id={rule._id} data={rule._source} />
                  )
              })
           }
           </ListView>
       </div>
    )
  }
}

class AlertInList extends React.Component {
    render() {
        var data = this.props.data;
        var ip_params = data.src_ip + '->' + data.dest_ip;
        return(
           <ListViewItem
            id={this.props.id}
            heading={data.alert.signature}
            description={ip_params}
           />
    )
    }
}
