import React from 'react';
import { ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import C3Chart from 'react-c3js';
import 'c3/c3.css';
import { PAGE_STATE } from './Const.js';
import { SciriusChart } from './Chart.js';

export class RuleInList extends React.Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    if (this.props.data.timeline) {
        this.props.data.timeline.type = 'bar';
    }
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
<Row>
<Col sm={11}>
<p>{this.props.data.content}</p>
      {this.props.data.timeline &&
      /* FIXME we should be dynamic on the width, auto don't work if we have just a few data */
      <SciriusChart data={ this.props.data.timeline } bar={{width: 10}}
               axis={{ x: { type: 'timeseries',
                            localtime: true,
                            min: this.props.from_date,
                            max: Date.now(),
                            tick: { fit: true, format: '%Y-%m-%d %H:%M'}
                     } }
                    }
      />
      }
</Col>
</Row>
</ListViewItem>
    )
  }
}

export class RuleCard extends React.Component {
  render() {
    var category = this.props.state.categories[this.props.data.category];
    if (this.props.data.timeline) {
        this.props.data.timeline.type = 'area';
    }
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
                    {this.props.data.created &&
                  <div className="col-md-4">Created: {this.props.data.created}</div>
                    }
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
               bar={{width: 2}}
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
