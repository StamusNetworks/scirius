import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import { ListView, ListViewItem, ListViewInfoItem, Row, Col, ListViewIcon } from 'patternfly-react';
import { VerticalNav, Dropdown, Icon, MenuItem } from 'patternfly-react';
import axios from 'axios';
import * as config from './config/Api.js';
import './App.css';
import 'bootstrap3/dist/css/bootstrap.css'
import 'patternfly/dist/css/patternfly.css'
import 'patternfly/dist/css/patternfly-additions.css'
import 'patternfly-react/dist/css/patternfly-react.css'

function onClick() {}

class HuntApp extends Component {
    render() {
        return(
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
            	    <VerticalNav.Masthead title="Scirius">
						<VerticalNav.Brand iconImg="/static/rules/stamus.png" titleImg="brand-alt.svg" />
						<VerticalNav.IconBar>
							<UserNavInfo/>
						</VerticalNav.IconBar>
					</VerticalNav.Masthead>
		   <VerticalNav.Item
            	      title="Home"
            	      iconClass="fa fa-home"
            	      initialActive
            	      onClick={onClick()}
            	      className={null}
            	    />

            	    <VerticalNav.Item
            	      title="Dashboards"
            	      iconClass="fa fa-tachometer"
            	      initialActive
            	      onClick={onClick()}
            	      className={null}
            	    >
            	        <VerticalNav.Badge count={42} />
            	    </VerticalNav.Item>
            	    <VerticalNav.Item title="IDS rules" iconClass="glyphicon glyphicon-eye-open">
            	        <VerticalNav.SecondaryItem title="Sources" onClick={onClick()}>
            	        	<VerticalNav.Badge count={9} tooltip="Whoa, that's a lot" />
            	        </VerticalNav.SecondaryItem>
       			<VerticalNav.SecondaryItem title="Rulesets" />
       	             </VerticalNav.Item>
       		     <VerticalNav.Item title="History" iconClass="glyphicon glyphicon-list">
       			<VerticalNav.SecondaryItem title="Item 3-A" />
       			<VerticalNav.SecondaryItem title="Item 3-B">
       				<VerticalNav.TertiaryItem title="Item 3-B-i" />
       				<VerticalNav.TertiaryItem title="Item 3-B-ii" />
       				<VerticalNav.TertiaryItem title="Item 3-B-iii" />
       			</VerticalNav.SecondaryItem>
       			<VerticalNav.SecondaryItem title="Item 3-C" />
       		     </VerticalNav.Item>
       		     <VerticalNav.Item 
		       title="Setup"
		       iconClass="glyphicon glyphicon-cog"
		       href="/appliances"
		     />
       		</VerticalNav>
       			<div className="container-fluid container-cards-pf container-pf-nav-pf-vertical">
       				<div className="row">
						<div className="col-xs-12 col-sm-12 col-md-12">
               				<RulesList />
						</div>
       				</div>
       			</div>
       		</div>
        )
    }
}

class UserNavInfo extends Component {
	render() {
		return(
			<React.Fragment>
    			<Dropdown componentClass="li" id="help">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="help" />
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Help</MenuItem>
        				<MenuItem>About</MenuItem>
      				</Dropdown.Menu>
    			</Dropdown>
			    <Dropdown componentClass="li" id="time">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="fa" name="clock-o" /> Last 24h
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Last 1h</MenuItem>
        				<MenuItem>Last 6h</MenuItem>
    				</Dropdown.Menu>
			   </Dropdown>
			    <Dropdown componentClass="li" id="user">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="user" /> Eric Leblond
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Preferences</MenuItem>
        				<MenuItem>Logout</MenuItem>
    				</Dropdown.Menu>
			   </Dropdown>
			</React.Fragment>
		)
	}
}

class RulesList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      rules: []
    };
  }

  componentDidMount() {
      axios.all([
          axios.get(config.API_URL + config.RULE_PATH + "?ordering=-created&limit=10"),
          axios.get(config.API_URL + config.CATEGORY_PATH + "?limit=100"),
	  ])
      .then(axios.spread((RuleRes, CatRes) => {
	 var categories_array = CatRes.data['results'];
	 var categories = {};
	 for (var i = 0; i < categories_array.length; i++) {
	     var cat = categories_array[i];
	     categories[cat.pk] = cat;
	 }
         this.setState({ rules: RuleRes.data['results'], categories: categories});
      }))
  }
  
  render() {
    var state = this.state;
    return (
        <div className="RulesList">
	    <ListView>
            {this.state.rules.map(function(rule) {
                return(
                   <RuleInList key={rule.pk} data={rule} state={state}/>
                )
             })}
	    </ListView>
        </div>
    );
  }
}

class RuleInList extends Component {
  handleClick = () => {
    //this.setState({rule: {this.props.data}});
    const rdata = <Rule rule={this.props.data}/>
    ReactDOM.render(rdata, document.getElementById('root'));
  }
  render() {
    var category = this.props.state.categories[this.props.data.category];
    return (
	<ListViewItem
  actions={<button onClick={this.handleClick}>View</button>}
  leftContent={<ListViewIcon name="envelope" />}
  additionalInfo={[<ListViewInfoItem key="created"><p>Created: {this.props.data.created}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="updated"><p>Updated: {this.props.data.updated}</p></ListViewInfoItem>,
                   <ListViewInfoItem key="category"><p>Category: {category.name}</p></ListViewInfoItem>
  ]}
  heading={this.props.data.sid}
  description={this.props.data.msg}
>
<Row>
<Col sm={11}>
{this.props.data.content}
</Col>
</Row>
</ListViewItem>
    )
  }
}


class Rule extends Component {
    render() {
        return (
            <h4>{this.props.rule.msg}</h4>
	)
    }
}

export default HuntApp;
