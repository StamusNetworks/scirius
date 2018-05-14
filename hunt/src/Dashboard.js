import React from 'react';
import axios from 'axios';
//import { SciriusChart } from './Chart.js';
import { DonutChart } from 'patternfly-react';
import * as config from './config/Api.js';

export class HuntDashboard extends React.Component {
    render() {
        return(
	    <div>
	       <h1>This is a dashboard</h1>
	       <HuntTrend from_date={this.props.from_date} />
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
	    axios.get(config.API_URL + config.ES_BASE_PATH +
                    'alerts_count&prev=1&hosts=*&from_date=' + this.props.from_date)
             .then(res => {
               this.setState({ data: res.data });
            })
    }

    componentDidMount() {
	    this.fetchData();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if (prevProps.from_date !==  this.props.from_date) {
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
	            ["previous", 100],
	            ["current", 0]
	            ],
	            groups: [
	              ["previous", "current"]
	            ]
	        };
	}
        return(
		<div>
		   {this.state.data &&
		      <DonutChart
		          data={g_data}
                          title={{type: "percent" }}
		      />
		   }
		</div>
	);
    }
}
