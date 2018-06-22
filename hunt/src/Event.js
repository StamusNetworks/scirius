import React from 'react';
import { Icon } from 'patternfly-react';

export class EventField extends React.Component {
   render() {
      return(
           <React.Fragment>
               <dt>{this.props.field_name}</dt>
	       <dd>
	           <EventValue field={this.props.field} value={this.props.value} addFilter={this.props.addFilter}/>
	       </dd>
           </React.Fragment>
	   )
   }
}

export class EventValue extends React.Component {
    constructor(props) {
       super(props);
       this.state = {display_actions: false };
    }

    render() {
        return(
	    <div
	        onMouseOver={e => {this.setState({display_actions: true})}}
	        onMouseOut={e => {this.setState({display_actions: false})}}
	       >
	       {this.props.value}
                     <span className={this.state.display_actions ? 'eventFilters' : 'eventFiltersHidden'} >
		         <a onClick={ e => {this.props.addFilter(this.props.field, this.props.value, false)}}> <Icon type="fa" name="search-plus"/></a>
		         <a onClick={ e => {this.props.addFilter(this.props.field, this.props.value, true)}}> <Icon type="fa" name="search-minus"/></a>
                     </span>
                {this.props.right_info && 
		    <span className="pull-right">{this.props.right_info}</span>
                }
	    </div>
	)
    }
}
