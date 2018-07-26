import React from 'react';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon } from 'patternfly-react';
import { Icon } from 'patternfly-react';
import { PAGINATION_VIEW, Row, Col} from 'patternfly-react';
import axios from 'axios';
import { HuntFilter } from './Filter.js';
import { HuntList, HuntPaginationRow } from './Api.js';
import * as config from './config/Api.js';
import { PAGE_STATE } from './Const.js';


const HistorySortFields = [
  {
    id: 'date',
    title: 'Date',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'username',
    title: 'User',
    isNumeric: false,
    defaultAsc: false,
  }
];


export class HistoryPage extends HuntList {
    constructor(props) {
	    super(props);
            var HistoryFilterFields = [
            {
                id: 'username',
                title: 'User',
                placeholder: 'Filter by User',
                filterType: 'text'
              }, {
                id: 'comment',
                title: 'Comment',
                placeholder: 'Filter by Comment',
                filterType: 'text'
              }, {
                id: 'action_type',
                title: 'Action Type',
                placeholder: 'Filter by Action Type',
                filterType: 'select',
                filterValues: []
              }
	    ];
  	    this.state = {data: [], count: 0, filter_fields: HistoryFilterFields};
	    this.fetchData = this.fetchData.bind(this)
    }

    fetchData(history_stat, filters) {
	    var string_filters = this.buildFilter(filters);
	    axios.get(config.API_URL + config.HISTORY_PATH + "?" + this.buildListUrlParams(history_stat) + string_filters)
        .then(res => {
               this.setState({ data: res.data, count: res.data.count });
          })
    
    }

    componentDidMount() {
	axios.get(config.API_URL + config.HISTORY_PATH + 'get_action_type_list/').then(
			res => {
				var filter_fields = Object.assign([], this.state.filter_fields);
				var actions;
				for (var field in filter_fields) {
					if (filter_fields[field].id !== 'action_type') {
						continue;
					}
					actions = filter_fields[field];
					break;
				}
				actions.filterValues = [];
				for (var item in res.data.action_type_list) {
					actions.filterValues.push({id: item, title: res.data.action_type_list[item]});
				}
				this.setState(filter_fields: filter_fields);
			}
		);
    }

    render() {
	return(
	    <div className="HistoryList">
               <HuntFilter ActiveFilters={this.props.filters}
                   config={this.props.config}
		   ActiveSort={this.props.config.sort}
		   UpdateFilter={this.UpdateFilter}
		   UpdateSort={this.UpdateSort}
		   setViewType={this.setViewType}
		   filterFields={this.state.filter_fields}
                   sort_config={HistorySortFields}
		   displayToggle={false}
	        />
	        <ListView>
	        {this.state.data.results &&
	           this.state.data.results.map( item => {
	               return(<HistoryItem key={item.pk} data={item} switchPage={this.props.switchPage} />);
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
	if (this.props.data.ua_objects.rule && this.props.data.ua_objects.rule.sid) {
		info.push(<ListViewInfoItem key="rule"><p><a onClick={e => { return this.props.switchPage(PAGE_STATE.rule, this.props.data.ua_objects.rule.sid);}}><Icon type="fa" name="bell" /> {this.props.data.ua_objects.rule.sid}</a></p></ListViewInfoItem>);
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

