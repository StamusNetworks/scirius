import React from 'react';

import PropTypes from 'prop-types';

import StyledSider from './StyledSider';

const Sider = ({ children }) => <StyledSider>{children}</StyledSider>;

Sider.propTypes = {
  children: PropTypes.any,
};

export default Sider;
