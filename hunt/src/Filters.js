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


import React from 'react';
import axios from 'axios';
import { PAGINATION_VIEW, ListView, ListViewItem, ListViewInfoItem, ListViewIcon} from 'patternfly-react';
import * as config from './config/Api.js';
import { HuntList, HuntPaginationRow } from './Api.js';
import { Modal, DropdownKebab, MenuItem, Icon, Button } from 'patternfly-react';
import { Form, FormGroup, FormControl } from 'patternfly-react';
import { Row, Col, Spinner} from 'patternfly-react';

import { HuntRestError } from './Error.js';

export class FiltersList extends HuntList {
    constructor(props) {
	    super(props);
  	    this.state = {data: [], count: 0, rulesets: []};
	    this.fetchData = this.fetchData.bind(this)
	    this.needUpdate = this.needUpdate.bind(this)
    }

    componentDidMount() {
    	if (this.state.rulesets.length === 0) {
             axios.get(config.API_URL + config.RULESET_PATH).then(res => {
               var rulesets = {}
               for (var index in res.data['results']) {
                    rulesets[res.data['results'][index].pk] = res.data['results'][index];
               }
               this.setState({rulesets: rulesets});
            })
	    }
	    this.fetchData(this.props.config, this.props.filters);
    }
    
    fetchData(filters_stat, filters) {
        this.setState({loading: true});
	    axios.get(config.API_URL + config.PROCESSING_PATH + "?" + this.buildListUrlParams(filters_stat))
            .then(res => {
               this.setState({ data: res.data.results, count: res.data.count, loading: false });
            }).catch(res => {
                    this.setState({loading: false});
            })
    }

    needUpdate() {
	    this.fetchData(this.props.config, this.props.filters);
    }

    render() {
	return(
	    <div>
	        <Spinner loading={this.state.loading} >
	        </Spinner>
	        <ListView>
	        {this.state.data &&
	           this.state.data.map( item => {
	               return(<FilterItem key={item.pk} data={item} switchPage={this.props.switchPage} last_index={this.state.count} needUpdate={this.needUpdate} rulesets={this.state.rulesets} from_date={this.props.from_date} />);
	           })
	        }
	        </ListView>
	        <HuntPaginationRow
	            viewType = {PAGINATION_VIEW.LIST}
	            pagination={this.props.config.pagination}
	            onPaginationChange={this.handlePaginationChange}
		    amountOfPages = {Math.ceil(this.state.count / this.props.config.pagination.perPage)}
		    pageInputValue = {this.props.config.pagination.page}
		    itemCount = {this.state.count - 1} // used as last item
		    itemsStart = {(this.props.config.pagination.page - 1) * this.props.config.pagination.perPage}
		    itemsEnd = {Math.min(this.props.config.pagination.page * this.props.config.pagination.perPage - 1, this.state.count - 1) }
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
    constructor(props) {
        super(props);
        this.state = { data: undefined, loading: true };
    }

    componentDidMount() {
	    this.fetchData(this.props.config, this.props.filters);
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
       if (prevProps.from_date !==  this.props.from_date) {
               this.fetchData(this.props.config, this.props.filters);
       }
    }
    
    fetchData(filters_stat, filters) {
        this.setState({loading: true});
	    axios.get(config.API_URL + config.ES_BASE_PATH + "poststats_summary&value=rule_filter_" + this.props.data.pk + "&from_date=" + this.props.from_date)
            .then(res => {
               this.setState({ data: res.data, loading: false });
            }).catch(res => {
                    this.setState({loading: false});
            })
    }
    
    render() {
        var item = this.props.data;
        var addinfo = [];
        for (var i in item.filter_defs) {
            var info = <ListViewInfoItem key={"filter-" + i}><p>{item.filter_defs[i].operator === "different" && "Not "}{item.filter_defs[i].key}: {item.filter_defs[i].value}</p></ListViewInfoItem>;
            addinfo.push(info);
        }
        if (Object.keys(this.props.rulesets).length > 0) {
            var rulesets = item.rulesets.map(item => { return(<ListViewInfoItem key={item + '-ruleset'}><p>Ruleset: {this.props.rulesets[item]['name']}</p></ListViewInfoItem>); });
            addinfo.push(rulesets);
        }
        var description = '';
        if (item.action !== 'suppress') {
            description = <ul className="list-inline">{Object.keys(item.options).map(option => { return(<li key={option}><strong>{option}</strong>: {item.options[option]}</li>) })}</ul>;
        }
        var icon = undefined;
        switch (item.action) {
            case 'suppress':
                icon =  <ListViewIcon name="close" />;
                break;
            case 'threshold':
                icon =  <ListViewIcon name="minus" />;
                break;
            case 'tag':
                icon =  <ListViewIcon name="envelope" />;
                break;
            case 'tagkeep':
                icon =  <ListViewIcon name="envelope" />;
                break;
            default:
                icon =  <ListViewIcon name="envelope" />;
                break;
        }
        var actions_menu = [<span key={item.pk  + '-index'} className="badge badge-default">{item.index}</span>];
        actions_menu.push(<FilterEditKebab key={item.pk + '-kebab'} data={item} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />);
        return(
            <ListViewItem
                key={item.pk + '-listitem'}
                leftContent={icon}
                additionalInfo = {addinfo}
                heading={item.action}
                description={description}
                actions={actions_menu}
            >
            {this.state.data &&
            <Row>
                {this.state.data.map( (item, idx) => {
                        return(
                    <div className="col-xs-3 col-sm-2 col-md-2" key={idx}>
                        <div className="card-pf card-pf-accented card-pf-aggregate-status">
                          <h2 className="card-pf-title">
                                <span className="fa fa-shield"></span>{item.key}
                          </h2>
                        <div className="card-pf-body">
                            <p className="card-pf-aggregate-status-notifications">
                              <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-ok"></span>{item.seen.value}</span>
                              <span className="card-pf-aggregate-status-notification"><span className="pficon pficon-error-circle-o"></span>{item.drop.value}</span>
                            </p>
                        </div>
                        </div> 
                    </div> 
                        )
                })
                }
            </Row>
            }
            </ListViewItem>
        )
    }
}

class FilterEditKebab extends React.Component {
    constructor(props) {
        super(props);
        this.displayToggle = this.displayToggle.bind(this);
        this.hideToggle = this.hideToggle.bind(this);
        this.state = { toggle: { show: false, action: "delete" }};
        this.closeAction = this.closeAction.bind(this);
    }

    displayToggle(action) {
        this.setState({toggle: {show: true, action: action}});
    }

    hideToggle() {
        this.setState({toggle: {show: false, action: this.state.toggle.action}});
    }

    closeAction() {
        this.setState({toggle: {show: false, action: 'delete'}});
    }

    render() {
        return(
            <React.Fragment>
                <DropdownKebab id="filterActions" pullRight>
                        {this.props.data.index !== 0 &&
                        <MenuItem  onClick={ e => {this.displayToggle("movetop") }}> 
                        Send Filter to top
                        </MenuItem>
                        }
                        <MenuItem  onClick={ e => {this.displayToggle("move") }}> 
                        Move Filter
                        </MenuItem>
                        <MenuItem  onClick={ e => {this.displayToggle("movebottom") }}> 
                        Send Filter to bottom
                        </MenuItem>
		                <MenuItem divider />
                        <MenuItem  onClick={ e => {this.displayToggle("delete") }}> 
                        Delete Filter
                        </MenuItem>
                </DropdownKebab>
	            <FilterToggleModal show={this.state.toggle.show} action={this.state.toggle.action} data={this.props.data}  close={this.closeAction} last_index={this.props.last_index} needUpdate={this.props.needUpdate}/>
            </React.Fragment>
        )
    }
}

class FilterToggleModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = { comment: "", new_index: 0,
            errors: undefined};
        this.close = this.close.bind(this);
        this.submit = this.submit.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleCommentChange = this.handleCommentChange.bind(this);
        this.onFieldKeyPress = this.onFieldKeyPress.bind(this);
    }


    componentDidUpdate(prevProps, prevState, snapshot) {
        if (prevProps.action !== this.props.action) {
            // Move to top / Launch dialog init with 0, then event to update new_index
            this.setState({new_index: 0});

            if (this.props.action === 'movebottom') {
                this.setState({new_index: this.props.last_index});
            }
        }
    }
    
    
    close() {
        this.setState({errors: undefined});
        this.props.close();
    }

    submit() {
            if (['move', 'movetop', 'movebottom'].indexOf(this.props.action) !== -1) {
                var data = {index: this.state.new_index, comment: this.state.comment}
	            axios.patch(config.API_URL + config.PROCESSING_PATH + this.props.data.pk + '/', data).then( res => {
                    console.log("Moved filter to " + this.state.new_index);
                    this.props.needUpdate();
                    this.close();
                }
                ).catch (error => {
                         console.log("action creation failure");
                         this.setState({errors: error.response.data});
                     });

            }
            if (this.props.action === 'delete') {
                var data = {comment: this.state.comment}
                axios({
                    url: config.API_URL + config.PROCESSING_PATH + this.props.data.pk + '/',
                    data: data,
                    method: 'delete'
                }).then(
                    res => {
                        console.log("Deleted filter");
                        this.props.needUpdate();
                        this.close();
                    }
                ).catch (error => {
                         console.log("action creation failure");
                         this.setState({errors: error.response.data});
                     }
                );
            }
    }

    handleCommentChange(event) {
        this.setState({comment: event.target.value});
    }

    handleChange(event) {
        const val = parseInt(event.target.value, 10);
        if (val >= 0) {
                this.setState({new_index: val});
        }
    }

    onFieldKeyPress(keyEvent) {
      if (keyEvent.key === 'Enter') {
        if (this.state.new_index < 0) {
          // Propagate event to trigger validation error
          return;
        }
        keyEvent.stopPropagation();
        keyEvent.preventDefault();
      }
    }

    render() {
       var action = this.props.action;
       switch (action) {
               case 'movetop':
                    action = 'Move to top';
                    break;
               case 'move':
                    action = 'Move';
                    break;
               case 'movebottom':
                    action = 'Move to bottom';
                    break;
               case 'delete':
                    action = 'Delete';
                    break;
               default:
                    break;
       }
       return(
            <Modal show={this.props.show} onHide={this.close}>
    <Modal.Header>
      <button
        className="close"
        onClick={this.close}
        aria-hidden="true"
        aria-label="Close"
      >
        <Icon type="pf" name="close" />
      </button>
      {this.props.data &&
        <Modal.Title>{action} {this.props.data.action} at current position {this.props.data.index}</Modal.Title>
      }
    </Modal.Header>
    <Modal.Body>
       <HuntRestError errors={this.state.errors} />
       <Form horizontal>
    {this.props.action === 'move' &&
        <FormGroup key="index" controlId="index" disabled={false}>
			<Col sm={3}>
			<strong>New index</strong>
			</Col>
			<Col sm={9}>
			<FormControl type="number" min={0} max={50000} disabled={false} defaultValue={0} onChange={this.handleChange} onKeyPress={e => this.onFieldKeyPress(e)} />
			</Col>
		   </FormGroup>

    }
        <div className="form-group">
            <div className="col-sm-9">
	    <strong>Optional comment</strong>
                <textarea value={this.state.comment} cols={70} onChange={this.handleCommentChange} />
            </div>
        </div>
        </Form>
    </Modal.Body>
    <Modal.Footer>
      <Button
        bsStyle="default"
        className="btn-cancel"
        onClick={this.close}
      >
        Cancel
      </Button>
      <Button bsStyle="primary" onClick={this.submit}>
        Submit
      </Button>
    </Modal.Footer>
  </Modal>
       )
    }
}
