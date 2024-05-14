import React from 'react';

import PropTypes from 'prop-types';

import * as Style from './style';

const PolicyParameters = ({ options }) =>
  Object.keys(options).map(option => (
    <Style.Parameter key={option}>
      <strong>{option}</strong>: {options[option]}
    </Style.Parameter>
  ));

PolicyParameters.propTypes = {
  options: PropTypes.objectOf(PropTypes.string).isRequired,
};

export default PolicyParameters;
