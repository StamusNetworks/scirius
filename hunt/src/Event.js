import React from 'react';
import { Icon } from 'patternfly-react';

export class EventField extends React.Component {
    constructor(props) {
       super(props);
       this.state = {display_actions: false };
    }

   render() {
      return(
           <React.Fragment>
               <dt>{this.props.field_name}</dt>
	       <dd
	           onMouseOver={e => {this.setState({display_actions: true})}}
	           onMouseOut={e => {this.setState({display_actions: false})}}
	       >{this.props.value}
	             {this.state.display_actions &&
		         <a onClick={ e => {this.props.addFilter(this.props.field, this.props.value)}}> <Icon type="fa" name="search-plus"/></a>
		     }
	       </dd>
           </React.Fragment>
	   )
   }
}
