import React from 'react';

import { InfoCircleFilled } from '@ant-design/icons';
import { Button, Modal } from 'antd';
import axios from 'axios';
import PropTypes from 'prop-types';

import ErrorHandler from 'ui/components/Error';
import EventIPDatascan from 'ui/components/EventIPDatascan';
import EventIPGeoloc from 'ui/components/EventIPGeoloc';
import EventIPPastries from 'ui/components/EventIPPastries';
import EventIPResolver from 'ui/components/EventIPResolver';
import EventIPSynscan from 'ui/components/EventIPSynscan';
import EventIPThreatlist from 'ui/components/EventIPThreatlist';

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
      axios.get(`https://www.onyphe.io/api/v2/summary/ip/${this.props.value}?apikey=${process.env.REACT_APP_ONYPHE_API_KEY}`).then(res => {
        this.setState({ ipinfo: res.data.results });
      });
    }
  }

  render() {
    const pastries = [];
    const resolvers = [];
    if (this.state.ipinfo) {
      this.state.ipinfo.map(item => {
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
        <a onClick={this.displayIPInfo} role="button">
          {' '}
          <InfoCircleFilled />
        </a>
        <Modal
          visible={this.state.show_ip_info}
          onCancel={this.closeIPInfo}
          title={
            <span>
              Some Info from{' '}
              <a href={`https://www.onyphe.io/search/?query=${this.props.value}`} target="_blank">
                {' '}
                Onyphe.io for {this.props.value}
              </a>
            </span>
          }
          footer={
            <Button className="btn-cancel" onClick={this.closeIPInfo}>
              Close
            </Button>
          }
        >
          {this.state.ipinfo && (
            <div>
              {this.state.ipinfo.map(item => {
                if (item['@category'] === 'geoloc') {
                  return (
                    <ErrorHandler>
                      <EventIPGeoloc data={item} />
                    </ErrorHandler>
                  );
                }
                if (item['@category'] === 'datascan') {
                  return (
                    <ErrorHandler>
                      <EventIPDatascan data={item} />
                    </ErrorHandler>
                  );
                }
                if (item['@category'] === 'synscan') {
                  return (
                    <ErrorHandler>
                      <EventIPSynscan data={item} />
                    </ErrorHandler>
                  );
                }
                if (item['@category'] === 'threatlist') {
                  return (
                    <ErrorHandler>
                      <EventIPThreatlist data={item} />
                    </ErrorHandler>
                  );
                }

                return null;
              })}
              {resolvers.length > 0 && (
                <ErrorHandler>
                  <EventIPResolver data={resolvers} />
                </ErrorHandler>
              )}
              {pastries.length > 0 && (
                <ErrorHandler>
                  <EventIPPastries data={pastries} />
                </ErrorHandler>
              )}
            </div>
          )}
          {this.state.ipinfo === null && <p>Fetching IP info</p>}
        </Modal>
      </React.Fragment>
    );
  }
}
EventIPInfo.propTypes = {
  value: PropTypes.any,
};
