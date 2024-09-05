import React from 'react';

import PropTypes from 'prop-types';
import WorldFlag from 'react-flagpack';
import './style.css';

const aliases = {
  GB: 'GB-UKM',
};
export const Flag = ({ country }) => (country ? <WorldFlag code={aliases[country] || country} size="m" /> : null);

Flag.propTypes = {
  country: PropTypes.string.isRequired,
};
