/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/


import React, { Component } from 'react';
import { VerticalNav, Dropdown, Icon, MenuItem } from 'patternfly-react';
import { AboutModal } from 'patternfly-react';
import { HuntDashboard } from './Dashboard.js';
import { HuntNotificationArea } from './Notifications.js';
import { HistoryPage } from './History.js';
import { PAGE_STATE } from './Const.js';
import { RulesList } from './Rule.js';
import { AlertsList } from './Alerts.js';
import { FiltersList } from './Filters.js';
import axios from 'axios';
import * as config from './config/Api.js';
import './pygments.css';
import './css/App.css';
import scirius_logo from './img/scirius-by-stamus.svg';
import keymap from './Keymap';
import { ShortcutManager } from 'react-shortcuts';
import PropTypes from 'prop-types';

const shortcutManager = new ShortcutManager(keymap);

class HuntApp extends Component {
  constructor(props) {
    super(props);
    this.timer = null;
    var interval = localStorage.getItem('interval');
    var duration = localStorage.getItem('duration');
    var rules_list_conf = localStorage.getItem('rules_list');
    var alerts_list_conf = localStorage.getItem('alerts_list');
    var history_conf = localStorage.getItem('history');
    var filters_list_conf = localStorage.getItem('filters_list');
    var page_display = localStorage.getItem('page_display');
    var ids_filters = localStorage.getItem('ids_filters');
    var history_filters = localStorage.getItem('history_filters');
    if (!duration) {
	    duration = 24;
    }

    if (!rules_list_conf) {
        rules_list_conf = {
            pagination: {
              page: 1,
              perPage: 6,
              perPageOptions: [6, 10, 15, 25]
            },
            sort: {id: 'created', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('rules_list', JSON.stringify(rules_list_conf));
    } else {
        rules_list_conf = JSON.parse(rules_list_conf);
    }

    if (!alerts_list_conf) {
        alerts_list_conf = {
            pagination: {
              page: 1,
              perPage: 20,
              perPageOptions: [20, 50, 100]
            },
            sort: {id: 'timestamp', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('alerts_list', JSON.stringify(alerts_list_conf));
    } else {
        alerts_list_conf = JSON.parse(alerts_list_conf);
    }

    if (!filters_list_conf) {
        filters_list_conf = {
            pagination: {
              page: 1,
              perPage: 20,
              perPageOptions: [20, 50, 100]
            },
            sort: {id: 'timestamp', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('filters_list', JSON.stringify(filters_list_conf));
    } else {
        filters_list_conf = JSON.parse(filters_list_conf);
    }

    if (!history_conf) {
        history_conf = {
            pagination: {
              page: 1,
              perPage: 6,
              perPageOptions: [6, 10, 15, 25, 50]
            },
            sort: {id: 'date', asc: false},
            view_type: 'list'
        };
        localStorage.setItem('history', JSON.stringify(history_conf));
    } else {
        history_conf = JSON.parse(history_conf);
    }

    if (!ids_filters) {
        ids_filters = [];
        localStorage.setItem('ids_filters', JSON.stringify(ids_filters));
    } else {
        ids_filters = JSON.parse(ids_filters);
    }

    if (!history_filters) {
        history_filters = [];
        localStorage.setItem('history_filters', JSON.stringify(history_filters));
    } else {
        history_filters = JSON.parse(history_filters);
    }


    if (!page_display) {
        page_display = { page: PAGE_STATE.rules_list, item:undefined };
        localStorage.setItem('page_display', JSON.stringify(page_display));
    } else {
        page_display = JSON.parse(page_display);
    }
    this.state = {
      sources: [], rulesets: [], duration: duration, from_date: (Date.now() - duration * 3600 * 1000),
      interval: interval,
      display: page_display,
      rules_list: rules_list_conf,
      alerts_list: alerts_list_conf,
      ids_filters: ids_filters,
      history: history_conf,
      history_filters: history_filters,
      filters_list: filters_list_conf,
    };
    this.displaySource = this.displaySource.bind(this);
    this.displayRuleset = this.displayRuleset.bind(this);
    this.changeDuration = this.changeDuration.bind(this);
    this.changeRefreshInterval = this.changeRefreshInterval.bind(this);

    this.fromDate = this.fromDate.bind(this);

    this.onHomeClick = this.onHomeClick.bind(this);
    this.onDashboardClick = this.onDashboardClick.bind(this);
    this.onHistoryClick = this.onHistoryClick.bind(this);
    this.onFiltersClick = this.onFiltersClick.bind(this);
    this.onAlertsClick = this.onAlertsClick.bind(this);
    this.switchPage = this.switchPage.bind(this);
    this.needReload = this.needReload.bind(this);
    this.updateRuleListState = this.updateRuleListState.bind(this);
    this.updateAlertListState = this.updateAlertListState.bind(this);
    this.updateIDSFilterState = this.updateIDSFilterState.bind(this);
    this.updateHistoryListState = this.updateHistoryListState.bind(this);
    this.updateHistoryFilterState = this.updateHistoryFilterState.bind(this);
    this.updateFilterListState = this.updateFilterListState.bind(this);
    
  }

    needReload() {
	this.setState({from_date: (Date.now() - this.state.duration * 3600 * 1000)});
    }

    onHomeClick() {
        this.switchPage(PAGE_STATE.rules_list, undefined);
    }
    
    onAlertsClick() {
        this.switchPage(PAGE_STATE.alerts_list, undefined);
    }
    
    onDashboardClick() {
        this.switchPage(PAGE_STATE.dashboards, undefined);
    }
    
    onHistoryClick() {
        this.switchPage(PAGE_STATE.history, undefined);
    }

    onFiltersClick() {
        this.switchPage(PAGE_STATE.filters_list, undefined);
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

      if (this.state.interval) {
          this.timer = setInterval(this.needReload, this.state.interval * 1000);
      }
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

   changeRefreshInterval(interval) {
	  this.setState({ interval: interval});
	  localStorage.setItem('interval', interval);

      if (interval) {
          if (this.timer) {
              clearInterval(this.timer);
              this.timer = null;
          }
          this.timer = setInterval(this.needReload, interval * 1000);
      } else {
          clearInterval(this.timer);
          this.timer = null;
      }
   }

  switchPage(page, item) {
      if (!page) {
	      console.log("switchPage called with null param");
	      return;
      }
      if (page === PAGE_STATE.rules_list && item !== undefined) {
          this.updateIDSFilterState([{label: "Signature ID: " + item, id: 'alert.signature_id', value: item, negated: false, query: 'filter'}]);
      }
      const page_display = {page: page, item: item};
      this.setState({display: page_display});
      localStorage.setItem('page_display', JSON.stringify(page_display));
  }
 
    updateRuleListState(rules_list_state) {
        this.setState({rules_list: rules_list_state});
        localStorage.setItem('rules_list', JSON.stringify(rules_list_state));
    }

    updateAlertListState(alerts_list_state) {
        this.setState({alerts_list: alerts_list_state});
        localStorage.setItem('alerts_list', JSON.stringify(alerts_list_state));
    }

    updateFilterListState(filters_list_state) {
        this.setState({filters_list: filters_list_state});
        localStorage.setItem('filters_list', JSON.stringify(filters_list_state));
    }

    updateIDSFilterState(filters) {
        this.setState({ids_filters: filters});
        localStorage.setItem('ids_filters', JSON.stringify(filters));
    }

    updateHistoryFilterState(filters) {
        this.setState({history_filters: filters});
        localStorage.setItem('history_filters', JSON.stringify(filters));
    }

    updateHistoryListState(history_state) {
        this.setState({history: history_state});
        localStorage.setItem('history', JSON.stringify(history_state));
    }

    getChildContext() {
        return { shortcuts: shortcutManager }
    }

    render() {
            var displayed_page = undefined;
            switch (this.state.display.page) {
               case PAGE_STATE.rules_list:
               default:
                  displayed_page = <RulesList config={this.state.rules_list} filters={this.state.ids_filters} from_date={this.state.from_date} SwitchPage={this.switchPage} updateListState={this.updateRuleListState} updateFilterState={this.updateIDSFilterState} />
                  break;
               case PAGE_STATE.source:
                  displayed_page = <SourcePage source={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.ruleset:
                  displayed_page = <RulesetPage ruleset={this.state.display.item} from_date={this.state.from_date}/>
                  break;
               case PAGE_STATE.dashboards:
	          // FIXME remove or change updateRuleListState
                  displayed_page = <HuntDashboard config={this.state.rules_list} filters={this.state.ids_filters} from_date={this.state.from_date} SwitchPage={this.switchPage} updateListState={this.updateRuleListState} updateFilterState={this.updateIDSFilterState} needReload={this.needReload} />
                  break;
               case PAGE_STATE.history:
                  displayed_page = <HistoryPage config={this.state.history} filters={this.state.history_filters} from_date={this.state.from_date} updateListState={this.updateHistoryListState} switchPage={this.switchPage} updateFilterState={this.updateHistoryFilterState}/>
                  break;
		case PAGE_STATE.alerts_list:
                  displayed_page = <AlertsList config={this.state.alerts_list} filters={this.state.ids_filters} from_date={this.state.from_date} updateListState={this.updateAlertListState} switchPage={this.switchPage} updateFilterState={this.updateIDSFilterState} />
		  break;
		case PAGE_STATE.filters_list:
                  displayed_page = <FiltersList config={this.state.filters_list} filters={this.state.filters_filters} from_date={this.state.from_date} updateListState={this.updateFilterListState} switchPage={this.switchPage} updateFilterState={this.updateFiltersFilterState} />
                  break;
            }
        return(
            <div className="layout-pf layout-pf-fixed faux-layout">
                <VerticalNav sessionKey="storybookItemsAsJsx" showBadges>
            	    <VerticalNav.Masthead title="Scirius">
						<VerticalNav.Brand titleImg={scirius_logo} />

						<VerticalNav.IconBar>
							<UserNavInfo ChangeDuration={this.changeDuration} ChangeRefreshInterval={this.changeRefreshInterval} interval={this.state.interval} period={this.state.duration} needReload={this.needReload}/>
						</VerticalNav.IconBar>


					</VerticalNav.Masthead>
		   <VerticalNav.Item
                      title="Signatures"
            	      iconClass="glyphicon glyphicon-eye-open"
            	      initialActive = { [PAGE_STATE.rules_list, PAGE_STATE.rule, PAGE_STATE.source, PAGE_STATE.ruleset].indexOf(this.state.display.page) >= 0 }
            	      onClick={this.onHomeClick}
            	      className={null}
            	    />
       		     <VerticalNav.Item
		      title="Alerts"
		      iconClass="pficon pficon-security"
            	      initialActive = { this.state.display.page === PAGE_STATE.alerts_list }
            	      onClick={this.onAlertsClick}
		     />
            	    <VerticalNav.Item
            	      title="Dashboard"
            	      iconClass="fa fa-tachometer"
            	      initialActive = { this.state.display.page === PAGE_STATE.dashboards }
            	      onClick={this.onDashboardClick}
            	      className={null}
            	    />
       		     <VerticalNav.Item
		      title="Actions"
		      iconClass="glyphicon glyphicon-filter"
            	      initialActive = { this.state.display.page === PAGE_STATE.filters_list }
            	      onClick={this.onFiltersClick}
		     />
       		     <VerticalNav.Item
		      title="History"
		      iconClass="glyphicon glyphicon-list"
            	      initialActive = { this.state.display.page === PAGE_STATE.history }
            	      onClick={this.onHistoryClick}
		     />
       		     <VerticalNav.Item 
		       title="Home"
		       iconClass="fa fa-home"
              	       initialActive = { this.state.display.page === PAGE_STATE.setup }
		       href="/rules"
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


const REFRESH_INTERVAL = {
  '': 'Off',
  10: '10s',
  30: '30s',
  60: '1m',
  120: '2m',
  300: '5m',
  900: '15m',
  1800: '30m',
  3600: '1h'
};

class UserNavInfo extends Component {
  constructor(props) {
    super(props);
    this.state = {
	    showModal: false,
	    showNotifications: false,
	    user: undefined,
    }
    this.AboutClick = this.AboutClick.bind(this);
    this.closeModal = this.closeModal.bind(this);
    this.toggleNotifications = this.toggleNotifications.bind(this);
  }

  componentDidMount() {
        axios.get(config.API_URL + config.USER_PATH + 'current_user/').then(
		res => {
			this.setState({user: res.data});
		}
	);
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
                var user = " ...";
		if (this.state.user !== undefined) {
			user = this.state.user.username;
		}
		return(
			<React.Fragment>

			    <Dropdown componentClass="li" id="timeinterval">
			        <Dropdown.Toggle useAnchor className="nav-item-iconic">
			            <Icon type="fa" name="clock-o" /> Refresh Interval {REFRESH_INTERVAL[this.props.interval]}
			        </Dropdown.Toggle>
			        <Dropdown.Menu>
			            {Object.keys(REFRESH_INTERVAL).map((interval) => {
			                return (<MenuItem key={interval} onClick={this.props.ChangeRefreshInterval.bind(this, interval)}>{REFRESH_INTERVAL[interval]}</MenuItem>)
			            }, this)}
			        </Dropdown.Menu>
			    </Dropdown>

			    <li className="dropdown">
			    <a id="refreshtime" role="button" className="nav-item-iconic" onClick={this.props.needReload}>
			    		<Icon type="fa" name="refresh" />
					</a>
			    </li>

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

			{this.state.showNotifications &&
			<HuntNotificationArea />
			}
    			<Dropdown componentClass="li" id="help">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="help" />
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
                                        <MenuItem href="/static/doc/hunt.html" target="_blank"><span className="glyphicon glyphicon-book"> </span> Help</MenuItem>
                                        <MenuItem onClick={this.AboutClick}><span className="glyphicon glyphicon-question-sign"> </span> About</MenuItem>
      				</Dropdown.Menu>
    			</Dropdown>

			    <Dropdown componentClass="li" id="user">
      				<Dropdown.Toggle useAnchor className="nav-item-iconic">
        				<Icon type="pf" name="user" /> {user}
      				</Dropdown.Toggle>
      				<Dropdown.Menu>
        				<MenuItem href="/accounts/edit"><span className="glyphicon glyphicon-cog"> </span> Account settings</MenuItem>
        				<MenuItem href="/accounts/logout"><span className="glyphicon glyphicon-log-out"> </span> Logout</MenuItem>
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

HuntApp.childContextTypes = {
  shortcuts: PropTypes.object.isRequired
}
