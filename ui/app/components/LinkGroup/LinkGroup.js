import React from 'react';

import PropTypes from 'prop-types';

import StyledLinkGroup from './StyledLinkGroup';

const LinkGroup = ({ children }) => <StyledLinkGroup>{children}</StyledLinkGroup>;

LinkGroup.propTypes = {
  children: PropTypes.any,
};

export default LinkGroup;
