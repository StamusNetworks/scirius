import React from 'react';
import { Switch } from 'antd';
import styled from 'styled-components';
import PropTypes from 'prop-types';

const SwitchHandler = styled.div`
  .ant-switch-checked {
    height: 18px;
    ${p => (p.activeBackgroundColor ? `background-color: ${p.activeBackgroundColor};` : '')}
    ${p => (p.activeBorderColor ? `border: 1px solid ${p.activeBorderColor};` : '')}
    ${p => (p.activeColor ? `.ant-switch-inner { color: ${p.activeColor}; }` : '')}
    ${p => (p.activeHandlerColor ? `.ant-switch-handle::before { background-color: ${p.activeHandlerColor}; }` : '')} #005792
  }
`;

const UISwitch = ({ activeColor, activeHandlerColor, activeBackgroundColor, activeBorderColor, ...props }) => (
  <SwitchHandler {...{ activeColor, activeHandlerColor, activeBackgroundColor, activeBorderColor }}>
    <Switch {...props} />
  </SwitchHandler>
);

export default UISwitch;

UISwitch.propTypes = {
  activeColor: PropTypes.string,
  activeHandlerColor: PropTypes.string,
  activeBackgroundColor: PropTypes.string,
  activeBorderColor: PropTypes.string,
};
