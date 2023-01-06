import React from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';

export const Parameter = styled.div`
  padding: 0 10px;
`;

const PolicyParameters = ({ policy }) =>
  Object.keys(policy.options).map(option => (
    <Parameter key={option}>
      <strong>{option}</strong>: {policy.options[option]}
    </Parameter>
  ));

PolicyParameters.propTypes = {
  policy: PropTypes.object.isRequired,
};

export default PolicyParameters;
