import React from 'react';
import PropTypes from 'prop-types';
import icons from 'ui/images/icons';
import { NormalToCamelCase } from 'ui/helpers';
import StyledLinkGroupTitle from './StyledLinkGroupTitle';

const LinkGroupTitle = ({title}) => {
  const i = NormalToCamelCase(title);
  return <StyledLinkGroupTitle>{icons[i] && <img src={icons[i]} alt={title} width={20} height={20} />} {title}</StyledLinkGroupTitle>
}

LinkGroupTitle.propTypes = {
  title: PropTypes.string,
}

export default LinkGroupTitle;
