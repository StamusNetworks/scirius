import React from 'react';
import { ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import axios from 'axios';
import { PAGE_STATE } from './Const.js';
import { SciriusChart } from './Chart.js';
import * as config from './config/Api.js';
import { ListGroup, ListGroupItem, Badge } from 'react-bootstrap';


export class RuleInList extends React.Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    return (
	<ListViewItem
  actions={<button onClick={this.props.SwitchPage.bind(this, PAGE_STATE.rule).bind(this, this.props.data)}>View</button>}
  leftContent={<ListViewIcon name="envelope" />}
  additionalInfo={[<ListViewInfoItem key="created"><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="updated"><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="category"><p>Category: {category.name}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="hits"><Spinner loading={this.props.data.hits === undefined} size="xs"><p>Alerts <span className="badge">{this.props.data.hits}</span></p></Spinner></ListViewInfoItem>
  ]}
  heading={this.props.data.sid}
  description={this.props.data.msg}
>
      {this.props.data.timeline &&
<Row>
<Col sm={11}>
<div className="container-fuild">
   <div className="row">
      <div className="col-md-10">
      <SciriusChart data={ this.props.data.timeline }
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                     } }
                    }
      />
      </div>
      <div className="col-md-2">
         <h4>Probes</h4>
         <ListGroup>
	    {this.props.data.probes.buckets.map( item => {
		return(<ListGroupItem key={item.key}>
		 {item.key}     
		 <Badge>{item.doc_count}</Badge>
		 </ListGroupItem>)
	    })}
         </ListGroup>
      </div>
   </div>
</div>
</Col>
</Row>
      }
</ListViewItem>
    )
  }
}

export class RuleCard extends React.Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    return (
    <div className="col-xs-6 col-sm-4 col-md-4">
	<div className="card-pf rule-card">
       <div className="card-pf-heading">
           <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.data.msg}>{this.props.data.msg}</h2>
       </div>
       <div className="card-pf-body">
            <div className="container-fluid">
               <div className="row">
                  <div className="col-md-5 truncate-overflow"  data-toggle="tooltip" title={category.name}>Cat: {category.name}</div>
                  <div className="col-md-4">
                    {this.props.data.created &&
                  <p>Created: {this.props.data.created}</p>
                    }
                  </div>
                  <div className="col-md-3">Alerts 
                     <Spinner loading={this.props.data.hits === undefined} size="xs">
                         <span className="badge">{this.props.data.hits}</span>
                     </Spinner>
                  </div>
                </div>
           </div>
           <Spinner loading={this.props.data.hits === undefined} size="xs">
      {this.props.data.timeline &&
      <div className="chart-pf-sparkline">
      <SciriusChart data={ this.props.data.timeline }
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            show: false
                     },
                     y: { show: false }
               }}
               legend = {{
                  show: false    
               }}
               size = {{ height: 50 }}
               point = {{ show: false }}
               from_date = {this.props.from_date}
      />
      </div>
      }
      {!this.props.data.timeline &&
          <div className="no-sparkline">
             <p>No alert</p>
          </div>
      }
           </Spinner>
         <div>
            SID: <strong>{this.props.data.sid}</strong>
            <span className="pull-right"><button onClick={this.props.SwitchPage.bind(this, PAGE_STATE.rule).bind(this, this.props.data)}>View</button></span>
         </div>
      </div>
   </div>
   </div>
    )
  }
}

export class RulePage extends React.Component {
    render() {
        return (
            <div>
            <h1>{this.props.rule.msg}</h1>
            <div className='container-fluid container-cards-pf'>
                <div className='row'>
                     <p>{this.props.rule.content}</p>
                     {this.props.rule.timeline &&
                        <SciriusChart data={ this.props.rule.timeline }
                            axis={{ x: { type: 'timeseries',
                                    localtime: true,
                                    min: this.props.from_date,
                                    max: Date.now(),
                                    tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                                    }
                                   }
                                 }
                         />
                      }
                </div>
                <div className='row row-cards-pf'>
                    <RuleStat title="Sources" rule={this.props.rule} item='src' from_date={this.props.from_date} />
                    <RuleStat title="Destinations" rule={this.props.rule} item='dest' from_date={this.props.from_date} />
                </div>
            </div>
            </div>
	)
    }
}

class RuleStat extends React.Component {
    constructor(props) {
	super(props);
  	this.state = {data: []};
    }

    componentDidMount() {
          axios.get(config.API_URL + config.ES_BASE_PATH +
                    'rule_' + this.props.item + '&from_date=' + this.props.from_date +
                    '&sid=' + this.props.rule.sid)
             .then(res => {
               console.log(res);
               this.setState({ data: res.data });
            })
    }

    render() {
        return (
	    <div className="col-xs-6 col-sm-4 col-md-4">
	<div className="card-pf rule-card">
       <div className="card-pf-heading">
           <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.title}>{this.props.title}</h2>
       </div>
       <div className="card-pf-body">
	<ListGroup>
	    {this.state.data.map( item => {
		return(<ListGroupItem key={item.key}>
		 {item.key}     
		 <Badge>{item.doc_count}</Badge>
		 </ListGroupItem>)
	    })}
	</ListGroup>
	</div>
        </div>
	</div>);
    }
}
