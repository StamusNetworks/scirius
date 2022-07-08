import React from 'react';
import PropTypes from 'prop-types';
import StyledLink from './StyledLink';

const Link = props => <StyledLink {...props}>{props.children}</StyledLink>;

Link.propTypes = {
  children: PropTypes.any,
};

export default Link;
