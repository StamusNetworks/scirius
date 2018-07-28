import React from 'react';
import axios from 'axios';
import { PAGINATION_VIEW, ListView, ListViewItem, ListViewInfoItem} from 'patternfly-react';
import * as config from './config/Api.js';
import { HuntList, HuntPaginationRow } from './Api.js';

export class FiltersList extends HuntList {
    constructor(props) {
	    super(props);
  	    this.state = {data: [], count: 0};
	    this.fetchData = this.fetchData.bind(this)
    }

    componentDidMount() {
	    this.fetchData(this.props.config, this.props.filters);
    }
    
    fetchData(history_stat, filters) {
	    axios.get(config.API_URL + config.PROCESSING_PATH)
            .then(res => {
               this.setState({ data: res.data, count: res.data.count });
            })
    }

    render() {
	return(
	    <div>

	        <ListView>
	        {this.state.data.results &&
	           this.state.data.results.map( item => {
	               return(<FilterItem key={item.pk} data={item} switchPage={this.props.switchPage} />);
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
        )
    }
}

class FilterItem extends React.Component {
    render() {
        var item = this.props.data;
        var addinfo = [];
        for (var i in item.filter_defs) {
            var info = <ListViewInfoItem key={"filter-" + i}><p>{item.filter_defs[i].key}: {item.filter_defs[i].value}</p></ListViewInfoItem>;
            addinfo.push(info);
        }
        var description = '';
        if (item.action !== 'suppress') {
            description = <ul className="list-inline">{Object.keys(item.options).map(option => { return(<li key={option}><strong>{option}</strong>: {item.options[option]}</li>) })}</ul>;
        }
        return(
            <ListViewItem
                key={item.pk}
                leftContent={<span className="label label-default">{item.pk}</span>}
                additionalInfo = {addinfo}
                heading={item.action}
                description={description}
            />
        )
    }
}
