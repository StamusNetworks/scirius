import React from 'react';
import { ListViewItem, ListViewInfoItem, ListViewIcon, Row, Col, Spinner } from 'patternfly-react';
import C3Chart from 'react-c3js';
import 'c3/c3.css';
import { PAGE_STATE } from './Const.js';

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
