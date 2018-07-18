import React from 'react';
import axios from 'axios';
import { Icon, Modal, Button, Row, Col } from 'patternfly-react';

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

class EventIPGeoloc extends React.Component {
	render() {
		return(
			<Col md={6}>
			        <h4>Geo localization result</h4>
				<dl>
				<dt>Country</dt><dd>{this.props.data.country_name}</dd>
				{this.props.data.city &&
				<React.Fragment>
					<dt>City</dt><dd>{this.props.data.city}</dd>
				</React.Fragment>
				}
				<dt>Organization</dt><dd>{this.props.data.organization}</dd>
				<dt>ASN</dt><dd>{this.props.data.asn}</dd>
				<dt>Subnet</dt><dd>{this.props.data.subnet}</dd>
			</dl>
			</Col>
		)
	}
}

class EventIPDatascan extends React.Component {
	render() {
		return(
			<Col md={6}>
			        <h4>Data scanner result</h4>
				<dl>
				{this.props.data.product &&
				<React.Fragment>
					<dt>Product</dt><dd>{this.props.data.product}</dd>
				</React.Fragment>
				}
				{this.props.data.productversion &&
				<React.Fragment>
					<dt>Version</dt><dd>{this.props.data.productversion}</dd>
				</React.Fragment>
				}
				{this.props.data.port &&
				<React.Fragment>
					<dt>Port</dt><dd>{this.props.data.port}</dd>
				</React.Fragment>
				}
				{this.props.data.data &&
				<React.Fragment>
					<dt>Data</dt><dd>{this.props.data.data.substring(0, 200)}</dd>
				</React.Fragment>
				}
				{this.props.data.seen_date &&
				<React.Fragment>
					<dt>Seen date</dt><dd>{this.props.data.seen_date}</dd>
				</React.Fragment>
				}
				</dl>
			</Col>
		)
	}
}

class EventIPSynscan extends React.Component {
	render() {
		return(
			<Col md={6}>
			        <h4>SYN scanner result</h4>
				<dl>
				{this.props.data.os &&
				<React.Fragment>
					<dt>Operating System</dt><dd>{this.props.data.os}</dd>
				</React.Fragment>
				}
				{this.props.data.port &&
				<React.Fragment>
					<dt>Port</dt><dd>{this.props.data.port}</dd>
				</React.Fragment>
				}
				{this.props.data.seen_date &&
				<React.Fragment>
					<dt>Seen date</dt><dd>{this.props.data.seen_date}</dd>
				</React.Fragment>
				}
				</dl>
			</Col>
		)
	}
}

class EventIPThreatlist extends React.Component {
	render() {
		return(
			<Col md={6}>
			        <h4>Threat list info</h4>
				<dl>
				{this.props.data["@type"] &&
				<React.Fragment>
					<dt>Type</dt><dd>{this.props.data["@type"]}</dd>
				</React.Fragment>
				}
				{this.props.data.threatlist &&
				<React.Fragment>
					<dt>Threat list</dt><dd>{this.props.data.threatlist}</dd>
				</React.Fragment>
				}
				{this.props.data.subnet &&
				<React.Fragment>
					<dt>Subnet</dt><dd>{this.props.data.subnet}</dd>
				</React.Fragment>
				}
				{this.props.data.seen_date &&
				<React.Fragment>
					<dt>Seen date</dt><dd>{this.props.data.seen_date}</dd>
				</React.Fragment>
				}
				</dl>
			</Col>
		)
	}
}

class EventIPResolver extends React.Component {
	render() {
		return(
			<Col md={6}>
			        <h4>Resolver info</h4>
				<dl>
				{this.props.data.map( item => {
					var value = "unknown";
					if (item["@type"] === "forward") {
						value = item.forward;
					}
					if (item["@type"] === "reverse") {
						value = item.reverse;
					}
					return(
						<React.Fragment>
							<dt>{item["@type"]}</dt><dd>{value} ({item.seen_date})</dd>
						</React.Fragment>
					)
				})
				}
				</dl>
			</Col>
		)
	}
}

class EventIPPastries extends React.Component {
	render() {
		var base_url = "https://pastebin.com/";
		return(
			<Col md={6}>
			        <h4>Pastries info</h4>
				<dl>
				{this.props.data.map( item => {
					if (item["@type"] === "pastebin") {
						return(
						<React.Fragment>
							<dt><a href={base_url + item.key} target="_blank">{base_url + item.key}</a></dt><dd>{item.seen_date}</dd>
						</React.Fragment>
						)
					} else {
						return null;
					}
				})
				}
				</dl>
			</Col>
		)
	}
}

class EventIPInfo extends React.Component {
	constructor(props) {
		super(props);
		this.state = { ipinfo: null, show_ip_info: false };
		this.displayIPInfo = this.displayIPInfo.bind(this);
		this.closeIPInfo = this.closeIPInfo.bind(this);
	}

	closeIPInfo() {
		this.setState({show_ip_info: false});
	}

	displayIPInfo() {
		this.setState({show_ip_info: true});
		if (this.state.ipinfo === null) {
			axios.get("https://www.onyphe.io/api/ip/" + this.props.value + "?apikey=" + process.env.REACT_APP_ONYPHE_API_KEY).then(
				res => {
					console.log(res.data['results']);
					this.setState({ipinfo: res.data['results']});	
				}
			);
		}
		
	}

	render() {
		var pastries = [];
		var resolvers = [];
		if (this.state.ipinfo) {
			this.state.ipinfo.map( item => {
				if (item["@category"] === "pastries") {
					pastries.push(item);
				}
				if (item["@category"] === "resolver") {
					resolvers.push(item);
				}
				return 1;
			})
		}
		return(
			<React.Fragment>
			<a onClick={this.displayIPInfo}> <Icon type="fa" name="info-circle"/></a>
			<Modal show={this.state.show_ip_info} onHide={this.closeIPInfo}>
				<Modal.Header>
					      <button
					        className="close"
					        onClick={this.closeIPInfo}
					        aria-hidden="true"
					        aria-label="Close"
					      >
       						 <Icon type="pf" name="close" />
     				 		</button>
					<Modal.Title>
						Some Info from <a href={"https://www.onyphe.io/search/?query=" + this.props.value} target="_blank">Onyphe.io for {this.props.value}</a>
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					{this.state.ipinfo &&
					      <Row>
						{this.state.ipinfo.map( item => {
							if (item["@category"] === "geoloc") {
								return(<EventIPGeoloc data={item}/>);
							}
							if (item["@category"] === "datascan") {
								return(<EventIPDatascan data={item}/>);
							}
							if (item["@category"] === "synscan") {
								return(<EventIPSynscan data={item}/>);
							}
							if (item["@category"] === "threatlist") {
								return(<EventIPThreatlist data={item}/>);
							}

							return null;
					})}
							{resolvers.length > 0 &&
								<EventIPResolver data={resolvers}/>
							}
							{pastries.length > 0 &&
								<EventIPPastries data={pastries}/>
							}
						</Row>
					}
					{this.state.ipinfo === null &&
					    <p>Fetching IP info</p>
					}
				</Modal.Body>
			    <Modal.Footer>
			      <Button
			        bsStyle="default"
			        className="btn-cancel"
			        onClick={this.closeIPInfo}
			      >
			        Close
			      </Button>
			    </Modal.Footer>
			</Modal>
			</React.Fragment>
		)
	}
}

class EventValueInfo extends React.Component {
    render() {
	if (['src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip'].indexOf(this.props.field) > -1 ) {
		if (process.env.REACT_APP_ONYPHE_API_KEY) {
			return(<EventIPInfo value={this.props.value} />);
		} else {
			return(
				<a href={"https://www.onyphe.io/search/?query=" + this.props.value} target="_blank"> <Icon type="fa" name="info-circle"/></a>
			);
		}
	} 
	return null;
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
		         <EventValueInfo field={this.props.field} value={this.props.value} />
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
