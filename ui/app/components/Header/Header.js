import React from 'react';
import PropTypes from 'prop-types';
import StyledHeader from './StyledHeader';

const Header = ({children}) => <StyledHeader>{children}</StyledHeader>

Header.propTypes = {
  children: PropTypes.any,
}

export default Header;
