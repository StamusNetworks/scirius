import React, { Component } from 'react';
import { VerticalNav, Dropdown, Icon, MenuItem } from 'patternfly-react';
import { AboutModal } from 'patternfly-react';
import { HuntDashboard } from './Dashboard.js';
import { HuntNotificationArea } from './Notifications.js';
import { HistoryPage } from './History.js';
import { PAGE_STATE } from './Const.js';
import { RulePage, RulesList } from './Rule.js';
import axios from 'axios';
import * as config from './config/Api.js';
import 'bootstrap3/dist/css/bootstrap.css'
import 'patternfly/dist/css/patternfly.css'
import 'patternfly/dist/css/patternfly-additions.css'
import 'patternfly-react/dist/css/patternfly-react.css'
import './App.css';
import scirius_logo from './img/scirius-by-stamus.svg';

class HuntApp extends Component {
  constructor(props) {
    super(props);
    var duration = localStorage.getItem('duration');
    var rules_list_conf = localStorage.getItem('rules_list');
    var history_conf = localStorage.getItem('history');
    var page_display = localStorage.getItem('page_display');
    if (!duration) {
	    duration = 24;
    }
    if (!rules_list_conf) {
        rules_list_conf = {
            pagination: {
              page: 1,
              perPage: 6,
              perPageOptions: [6, 10, 15, 25, 50]
            },
            filters: [],
            sort: {id: 'created', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('rules_list', JSON.stringify(rules_list_conf));
    } else {
        rules_list_conf = JSON.parse(rules_list_conf);
    }

    if (!history_conf) {
        history_conf = {
            pagination: {
              page: 1,
              perPage: 6,
              perPageOptions: [6, 10, 15, 25, 50]
            },
            filters: [],
            sort: {id: 'date', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('history', JSON.stringify(history_conf));
    } else {
        history_conf = JSON.parse(history_conf);
    }

    if (!page_display) {
        page_display = { page: PAGE_STATE.rules_list, item:undefined };
        localStorage.setItem('page_display', JSON.stringify(page_display));
    } else {
        page_display = JSON.parse(page_display);
    }
    this.state = {
      sources: [], rulesets: [], duration: duration, from_date: (Date.now() - duration * 3600 * 1000),
      display: page_display,
      rules_list: rules_list_conf,
      history: history_conf
    };
    this.displaySource = this.displaySource.bind(this);
    this.displayRuleset = this.displayRuleset.bind(this);
    this.changeDuration = this.changeDuration.bind(this);

    this.fromDate = this.fromDate.bind(this);

    this.onHomeClick = this.onHomeClick.bind(this);
    this.onDashboardClick = this.onDashboardClick.bind(this);
    this.onHistoryClick = this.onHistoryClick.bind(this);
    this.switchPage = this.switchPage.bind(this);
    this.updateRuleListState = this.updateRuleListState.bind(this);
    this.updateHistoryListState = this.updateHistoryListState.bind(this);
    
  }

    onHomeClick() {
        this.switchPage(PAGE_STATE.rules_list, undefined);
    }
    
    
    onDashboardClick() {
        this.switchPage(PAGE_STATE.dashboards, undefined);
    }
    
    onHistoryClick() {
        this.switchPage(PAGE_STATE.history, undefined);
    }

    fromDate(period) {
	const duration = period * 3600 * 1000;
	return Date.now() - duration;
    }

    componentDidMount() {
      axios.all([
          axios.get(config.API_URL + config.SOURCE_PATH),
          axios.get(config.API_URL + config.RULESET_PATH),
	  ])
      .then(axios.spread((SrcRes, RulesetRes) => {
         this.setState({ rulesets: RulesetRes.data['results'], sources: SrcRes.data['results']});
      }))
    }

    displayRuleset(ruleset) {
        this.switchPage(PAGE_STATE.ruleset, ruleset);
    }
    
    displaySource(source) {
        this.switchPage(PAGE_STATE.source, source);
    }

   changeDuration(period) {
	this.setState({ duration: period, from_date: this.fromDate(period)});
	localStorage.setItem('duration', period);
   }

  switchPage(page, item) {
      if (!page) {
	      console.log("switchPage called with null param");
	      return;
      }
      const page_display = {page: page, item: item};
      this.setState({display: page_display});
      localStorage.setItem('page_display', JSON.stringify(page_display));
  }
 
    updateRuleListState(rules_list_state) {
        this.setState({rules_list: rules_list_state});
        localStorage.setItem('rules_list', JSON.stringify(rules_list_state));
    }

    updateHistoryListState(history_state) {
        this.setState({history: history_state});
        localStorage.setItem('history', JSON.stringify(history_state));
    }

    render() {
            var displayed_page = undefined;
            switch (this.state.display.page) {
               case PAGE_STATE.rules_list:
               default:
                  displayed_page = <RulesList config={this.state.rules_list} from_date={this.state.from_date} SwitchPage={this.switchPage} updateListState={this.updateRuleListState} />
                  break;
               case PAGE_STATE.source:
                  displayed_page = <SourcePage source={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.ruleset:
                  displayed_page = <RulesetPage ruleset={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.rule:
                  displayed_page = <RulePage rule={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.dashboards:
                  displayed_page = <HuntDashboard from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.history:
                  displayed_page = <HistoryPage config={this.state.history} from_date={this.state.from_date} updateListState={this.updateHistoryListState} />
                  break;
            }
        return(
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
            	    <VerticalNav.Masthead title="Scirius">
						<VerticalNav.Brand titleImg={scirius_logo} />
						<VerticalNav.IconBar>
							<UserNavInfo ChangeDuration={this.changeDuration} period={this.state.duration}/>
						</VerticalNav.IconBar>
					</VerticalNav.Masthead>
		   <VerticalNav.Item
            	      title="Home"
            	      iconClass="fa fa-home"
            	      initialActive = { this.state.display.page === PAGE_STATE.rules_list }
            	      onClick={this.onHomeClick}
            	      className={null}
            	    />

            	    <VerticalNav.Item
            	      title="Dashboards"
            	      iconClass="fa fa-tachometer"
            	      initialActive = { this.state.display.page === PAGE_STATE.dashboards }
            	      onClick={this.onDashboardClick}
            	      className={null}
            	    >
            	    </VerticalNav.Item>
            	    <VerticalNav.Item title="IDS rules" iconClass="glyphicon glyphicon-eye-open">
            	        <VerticalNav.SecondaryItem title="Sources" >
                	    {this.state.sources.map(function(source) {
				    return(
	    		     <VerticalNav.TertiaryItem key={source.pk} title={source.name}  onClick={this.displaySource.bind(this, source)}  />
			     )
			     }, this)}
	    		     <VerticalNav.TertiaryItem title="Add Source" href="/rules/source/add" />
            	        </VerticalNav.SecondaryItem>
       			<VerticalNav.SecondaryItem title="Rulesets">
                	    {this.state.rulesets.map(function(ruleset) {
				    return(
	    		     <VerticalNav.TertiaryItem key={ruleset.pk} title={ruleset.name} onClick={this.displayRuleset.bind(this, ruleset)} />
			     )
			     }, this)}
	    		     <VerticalNav.TertiaryItem title="Add Ruleset" href="/rules/ruleset/add" >
        			<Icon type="pf" name="help" />
			     </VerticalNav.TertiaryItem>
            	        </VerticalNav.SecondaryItem>
       	             </VerticalNav.Item>
       		     <VerticalNav.Item
		      title="History"
		      iconClass="glyphicon glyphicon-list"
            	      initialActive = { this.state.display.page === PAGE_STATE.history }
            	      onClick={this.onHistoryClick}
		     />
       		     <VerticalNav.Item 
		       title="Setup"
		       iconClass="glyphicon glyphicon-cog"
              	       initialActive = { this.state.display.page === PAGE_STATE.setup }
		       href="/appliances"
		     />
       		</VerticalNav>
       		<div className="container-fluid container-cards-pf container-pf-nav-pf-vertical nav-pf-persistent-secondary">
       			<div className="row row-cards-pf">
			    <div className="col-xs-12 col-sm-12 col-md-12" id="app-content" >
                                {displayed_page}
	       	            </div>
       	         	</div>
       	        </div>
       	    </div>
        )
    }
}


const USER_PERIODS = {
  1: '1h',
  6: '6h',
  24: '24h',
  48: '2d',
  168: '7d',
  720: '30d'
};

class UserNavInfo extends Component {
  constructor(props) {
    super(props);
    this.state = {
	    showModal: false,
	    showNotifications: false
    }
    this.AboutClick = this.AboutClick.bind(this);
    this.closeModal = this.closeModal.bind(this);
    this.toggleNotifications = this.toggleNotifications.bind(this);
  }

  AboutClick(e) {
	  this.setState({showModal: true});
  }
  closeModal(e) {
	  this.setState({showModal: false});
  }
  toggleNotifications(e) {
	  this.setState({showNotifications: !this.state.showNotifications});
  }

	render() {
		return(
			<React.Fragment>
        		<li className="dropdown">
			   <a id="notifications" className="nav-item-iconic" onClick={this.toggleNotifications}>
			      <Icon type="fa" name="bell" />
			   </a>
			</li>
			{this.state.showNotifications &&
			<HuntNotificationArea />
			}
    			<Dropdown componentClass="li" id="help">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="help" />
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem>Help</MenuItem>
        				<MenuItem onClick={this.AboutClick}>About</MenuItem>
      				</Dropdown.Menu>
    			</Dropdown>
			    <Dropdown componentClass="li" id="time">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="fa" name="clock-o" /> Last {USER_PERIODS[this.props.period]}
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
				        {Object.keys(USER_PERIODS).map((period) => {
        				return (<MenuItem key={period} onClick={this.props.ChangeDuration.bind(this, period)}>Last {USER_PERIODS[period]}</MenuItem>)
					}, this)}
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
			   
        <AboutModal
          show={this.state.showModal}
          onHide={this.closeModal}
          productTitle="Scirius Enterprise Edition"
          logo={scirius_logo}
          altLogo="SEE Logo"
          trademarkText="Copyright 2014-2018, Stamus Networks"
        >
          <AboutModal.Versions>
            <AboutModal.VersionItem label="Version" versionText="31.0.0" />
          </AboutModal.Versions>
        </AboutModal>
			</React.Fragment>
		)
	}
}


class SourcePage extends Component {
    render() {
	var source = this.props.source;
        return (
            <h1>{source.name}</h1>
	)
    }
}

class RulesetPage extends Component {
    render() {
	var ruleset = this.props.ruleset;
        return (
            <h1>{ruleset.name}</h1>
	)
    }
}

export default HuntApp;
