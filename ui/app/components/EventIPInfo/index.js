import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Button, Modal } from 'antd';
import { InfoCircleFilled } from '@ant-design/icons';
import EventIPGeoloc from 'components/EventIPGeoloc';
import EventIPDatascan from 'components/EventIPDatascan';
import EventIPSynscan from 'components/EventIPSynscan';
import EventIPThreatlist from 'components/EventIPThreatlist';
import EventIPResolver from 'components/EventIPResolver';
import EventIPPastries from 'components/EventIPPastries';
import ErrorHandler from 'components/Error';

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
      axios.get(`https://www.onyphe.io/api/v2/summary/ip/${this.props.value}?apikey=${process.env.REACT_APP_ONYPHE_API_KEY}`).then((res) => {
        this.setState({ ipinfo: res.data.results });
      });
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
              {this.state.ipinfo.map((item) => {
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
