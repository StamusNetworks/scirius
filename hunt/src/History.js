import React from 'react';
import { ListView, ListViewItem, ListViewInfoItem, ListViewIcon } from 'patternfly-react';
import { Row, Col, Spinner, Icon } from 'patternfly-react';
import axios from 'axios';
import * as config from './config/Api.js';

export class HistoryPage extends React.Component {
    constructor(props) {
	    super(props);
  	    this.state = {data: []};
    }

    componentDidMount() {
          axios.get(config.API_URL + config.HISTORY_PATH)
          .then(res => {
	       console.log(res.data);
               this.setState({ data: res.data });
          })
    }

    render() {
	return(
	    <ListView>
	    {this.state.data.results &&
	       this.state.data.results.map( item => {
	           return(<HistoryItem key={item.id} data={item} />);
	       })
	    }
	    </ListView>
	);
    }
}


class HistoryItem extends React.Component {
    render() {
        return(
	    <ListViewItem
	        leftContent={<ListViewIcon name="envelope" />}
	        additionalInfo={[<ListViewInfoItem key="date"><p>Date: {this.props.data.date}</p></ListViewInfoItem>,
			   <ListViewInfoItem key="user"><p><Icon type="pf" name="user" /> {this.props.data.username}</p></ListViewInfoItem>
	        ]}
	        heading={this.props.data.action_type}
	        description={this.props.data.description}
	     />
	)
    }
}

