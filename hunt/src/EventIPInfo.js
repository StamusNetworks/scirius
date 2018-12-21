import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Modal, Button, Icon, Row } from 'patternfly-react';
import EventIPGeoloc from './EventIPGeoloc';
import EventIPDatascan from './EventIPDatascan';
import EventIPSynscan from './EventIPSynscan';
import EventIPThreatlist from './EventIPThreatlist';
import EventIPResolver from './EventIPResolver';
import EventIPPastries from './EventIPPastries';

export default class EventIPInfo extends React.Component {
    constructor(props) {
        super(props);
        this.state = { ipinfo: null, show_ip_info: false };
        this.displayIPInfo = this.displayIPInfo.bind(this);
        this.closeIPInfo = this.closeIPInfo.bind(this);
    }

    closeIPInfo() {
        this.setState({ show_ip_info: false });
    }

    displayIPInfo() {
        this.setState({ show_ip_info: true });
        if (this.state.ipinfo === null) {
            axios.get(`https://www.onyphe.io/api/ip/${this.props.value}?apikey=${process.env.REACT_APP_ONYPHE_API_KEY}`).then(
                (res) => {
                    this.setState({ ipinfo: res.data.results });
                }
            );
        }
    }

    render() {
        const pastries = [];
        const resolvers = [];
        if (this.state.ipinfo) {
            this.state.ipinfo.map((item) => {
                if (item['@category'] === 'pastries') {
                    pastries.push(item);
                }
                if (item['@category'] === 'resolver') {
                    resolvers.push(item);
                }
                return 1;
            });
        }
        return (
            <React.Fragment>
                <a onClick={this.displayIPInfo} role={'button'}> <Icon type="fa" name="info-circle" /></a>
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
                            Some Info from <a href={`https://www.onyphe.io/search/?query=${this.props.value}`} target="_blank">Onyphe.io for {this.props.value}</a>
                        </Modal.Title>
                    </Modal.Header>
                    <Modal.Body>
                        {this.state.ipinfo && <Row>
                            {this.state.ipinfo.map((item) => {
                                if (item['@category'] === 'geoloc') {
                                    return (<EventIPGeoloc data={item} />);
                                }
                                if (item['@category'] === 'datascan') {
                                    return (<EventIPDatascan data={item} />);
                                }
                                if (item['@category'] === 'synscan') {
                                    return (<EventIPSynscan data={item} />);
                                }
                                if (item['@category'] === 'threatlist') {
                                    return (<EventIPThreatlist data={item} />);
                                }

                                return null;
                            })}
                            {resolvers.length > 0 && <EventIPResolver data={resolvers} />}
                            {pastries.length > 0 && <EventIPPastries data={pastries} />}
                        </Row>}
                        {this.state.ipinfo === null && <p>Fetching IP info</p>}
                    </Modal.Body>
                    <Modal.Footer>
                        <Button
                            bsStyle="default"
                            className="btn-cancel"
                            onClick={this.closeIPInfo}
                        >Close
                        </Button>
                    </Modal.Footer>
                </Modal>
            </React.Fragment>
        );
    }
}
EventIPInfo.propTypes = {
    value: PropTypes.any,
};
