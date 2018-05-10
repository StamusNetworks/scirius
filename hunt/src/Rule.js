import React from 'react';
import { ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import C3Chart from 'react-c3js';
import 'c3/c3.css';
import { PAGE_STATE } from './Const.js';

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
      <C3Chart data={ this.props.data.timeline } bar={{width: 10}}
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
            <ul className="list-inline list-full">
             <li className="pull-left">Cat: {category.name}</li>
             {this.props.data.created &&
             <li>Created: {this.props.data.created}</li>
             }
               <li className="pull-right">Alerts 
               
           <Spinner loading={this.props.data.hits === undefined} size="xs">
               <span className="badge">{this.props.data.hits}</span>
           </Spinner>
         </li>
          </ul>
           <Spinner loading={this.props.data.hits === undefined} size="xs">
      {this.props.data.timeline &&
      <div className="chart-pf-sparline">
      <C3Chart data={ this.props.data.timeline }
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
      />
      </div>
      }
      {!this.props.data.timeline &&
          <div className="no-sparline">
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
