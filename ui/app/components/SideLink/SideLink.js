import React from 'react';
import PropTypes from 'prop-types';
import StyledSideLink from './StyledSideLink';

const SideLink = props => <StyledSideLink {...props}>{props.children}</StyledSideLink>;

SideLink.propTypes = {
  children: PropTypes.any,
};

export default SideLink;
