import React, { useState, useEffect } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { createStructuredSelector } from 'reselect';
import styled from 'styled-components';
import { Spin } from 'antd';
import LaunchRounded from '@material-ui/icons/LaunchRounded';

import * as config from 'ui/config';
import request from 'utils/request';
import selectors from 'ui/containers/App/selectors';

const AppsContainer = styled.div`
  width: 100px;
  height: 96px;
  display: flex;
  flex-direction: column;

  & > .ant-spin {
    height: 96px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
`;

const AppItem = styled.a`
  height: 32px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 5px;
  transition: all 0.3s;

  &:hover {
    background-color: #f0f0f0 !important;
  }

  & > img {
    width: 14px;
    height: 14px;
  }
`;

const IconLabel = styled.div`
  color: #005792;
`;

function SwitchApps({ user }) {
  const {
    data: { permissions = [] },
    request: { loading },
  } = user;
  const [systemSettings, setSystemSettings] = useState({});

  useEffect(() => {
    (async () => setSystemSettings(await request(config.SYSTEM_SETTINGS_PATH)))();
  }, []);

  return (
    <React.Fragment>
      <AppsContainer>
        {systemSettings.kibana && permissions.includes('rules.events_kibana') && (
          <AppItem href={systemSettings.kibana_url} target="_blank">
            <IconLabel>Kibana</IconLabel>
            <LaunchRounded style={{ color: 'currentColor', strokeWidth: 1.5, fill: '#005792' }} />
          </AppItem>
        )}
        {systemSettings.evebox && permissions.includes('rules.events_evebox') && (
          <AppItem href={systemSettings.evebox_url} target="_blank">
            <IconLabel>EveBox</IconLabel>
            <LaunchRounded style={{ color: 'currentColor', strokeWidth: 1.5, fill: '#005792' }} />
          </AppItem>
        )}
        {systemSettings.cyberchef && (
          <AppItem href={systemSettings.cyberchef_url} target="_blank">
            <IconLabel>CyberChef</IconLabel>
            <LaunchRounded style={{ color: 'currentColor', strokeWidth: 1.5, fill: '#005792' }} />
          </AppItem>
        )}
        {loading && <Spin />}
      </AppsContainer>
    </React.Fragment>
  );
}

SwitchApps.propTypes = {
  user: PropTypes.shape({
    data: PropTypes.object,
    request: PropTypes.object,
  }).isRequired,
};

const mapStateToProps = createStructuredSelector({
  user: selectors.makeSelectUser(),
});

export default connect(mapStateToProps)(SwitchApps);
