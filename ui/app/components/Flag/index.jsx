import * as React from 'react';

import PropTypes from 'prop-types';

import './style.css';

import flagList from '../../assets/flags/index';

export const Flag = ({ code = 'NL', size = 's', gradient = '', hasBorder = true, hasDropShadow = false, hasBorderRadius = true, className }) => (
  <div
    className={`flag ${gradient} size-${size} ${hasBorder ? 'border' : ''} ${hasDropShadow ? 'drop-shadow' : ''} ${
      hasBorderRadius ? 'border-radius' : ''
    } ${className ? className.replace(/\s\s+/g, ' ').trim() : ''}`}
  >
    <img src={flagList[code]} alt={code} />
  </div>
);

Flag.propTypes = {
  code: PropTypes.string.isRequired,
  size: PropTypes.string,
  gradient: PropTypes.oneOf(['', 'top-down', 'real-circular', 'real-linear']),
  hasBorder: PropTypes.bool,
  hasDropShadow: PropTypes.bool,
  hasBorderRadius: PropTypes.bool,
  className: PropTypes.string,
};
