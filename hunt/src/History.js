import React from 'react';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon } from 'patternfly-react';
import { Icon } from 'patternfly-react';
import { PAGINATION_VIEW, Row, Col} from 'patternfly-react';
import axios from 'axios';
import { HuntFilter } from './Filter.js';
import { HuntList, HuntPaginationRow } from './Api.js';
import * as config from './config/Api.js';

const HistoryFilterFields = [
  {
    id: 'msg',
    title: 'Message',
    placeholder: 'Filter by Message',
    filterType: 'text'
  }, {
    id: 'user',
    title: 'User',
    placeholder: 'Filter by User',
    filterType: 'text'
  }
];

const HistorySortFields = [
  {
    id: 'date',
    title: 'Date',
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
    id: 'username',
    title: 'Username',
    isNumeric: true,
    defaultAsc: false,
  }
];


export class HistoryPage extends HuntList {
    constructor(props) {
	    super(props);
  	    this.state = {data: [], count: 0};
	    this.fetchData = this.fetchData.bind(this)
    }

    componentDidMount() {
	this.fetchData(this.props.config);
    }
    
    
    fetchData(history_stat) {
	axios.get(config.API_URL + config.HISTORY_PATH + this.buildListUrlParams(history_stat))
        .then(res => {
               this.setState({ data: res.data, count: res.data.count });
          })
    
    }

    render() {
	return(
	    <div>
               <HuntFilter ActiveFilters={this.props.config.filters}
                   config={this.props.config}
		   ActiveSort={this.props.config.sort}
		   UpdateFilter={this.UpdateFilter}
		   UpdateSort={this.UpdateSort}
		   setViewType={this.setViewType}
		   filterFields={HistoryFilterFields}
                   sort_config={HistorySortFields}
		   displayToggle={false}
	        />
	        <ListView>
	        {this.state.data.results &&
	           this.state.data.results.map( item => {
	               return(<HistoryItem key={item.id} data={item} />);
	           })
	        }
	        </ListView>
	    <HuntPaginationRow
	        viewType = {PAGINATION_VIEW.LIST}
	        pagination={this.props.config.pagination}
	        onPaginationChange={this.handlePaginationChange}
		amountOfPages = {Math.ceil(this.state.count / this.props.config.pagination.perPage)}
		pageInputValue = {this.props.config.pagination.page}
		itemCount = {this.state.count}
		itemsStart = {(this.props.config.pagination.page - 1) * this.props.config.pagination.perPage}
		itemsEnd = {Math.min(this.props.config.pagination.page * this.props.config.pagination.perPage - 1, this.state.count) }
		onFirstPage={this.onFirstPage}
		onNextPage={this.onNextPage}
		onPreviousPage={this.onPrevPage}
		onLastPage={this.onLastPage}

	    />

	    </div>
	);
    }
}


class HistoryItem extends React.Component {
    render() {
	var date = new Date(Date.parse(this.props.data.date)).toLocaleString('en-GB', { timeZone: 'UTC' });
	var info= [<ListViewInfoItem key="date"><p>Date: {date}</p></ListViewInfoItem>,
			   <ListViewInfoItem key="user"><p><Icon type="pf" name="user" /> {this.props.data.username}</p></ListViewInfoItem>
	        ];
	if (this.props.data.ua_objects.ruleset && this.props.data.ua_objects.ruleset.pk) {
		info.push(<ListViewInfoItem key="ruleset"><p><Icon type="fa" name="th" /> {this.props.data.ua_objects.ruleset.value}</p></ListViewInfoItem>);
	}
        return(
	    <ListViewItem
	        leftContent={<ListViewIcon name="envelope" />}
	        additionalInfo={info}
	        heading={this.props.data.action_type}
	        description={this.props.data.description}
		key={this.props.data.pk}
	     >
	       {this.props.data.comment &&
	       <Row>
	           <Col sm={11}>
		        <div className="container-fluid">
			   <strong>Comment</strong>
		           <p>{this.props.data.comment}</p>
		   	</div>
		   </Col>
	       </Row>
	       }
	     </ListViewItem>
	)
    }
}

