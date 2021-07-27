import React from 'react';
import PropTypes from 'prop-types';
import StyledContent from './StyledContent';

const Content = ({children}) => <StyledContent>{children}</StyledContent>

Content.propTypes = {
  children: PropTypes.any,
}

export default Content;
