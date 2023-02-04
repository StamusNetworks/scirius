import React from 'react';
import PropTypes from 'prop-types';
import { ActionButton } from '../styles';

const LoadFilterSetButton = ({ onClick }) => (
  <ActionButton active>
    <svg height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
      <path d="M0 0h24v24H0V0z" fill="none" />
      <path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z" />
    </svg>
    <a
      onClick={e => {
        e.preventDefault();
        onClick();
      }}
    >
      Load Filter Set
    </a>
  </ActionButton>
);

export default LoadFilterSetButton;

LoadFilterSetButton.propTypes = {
  onClick: PropTypes.func.isRequired,
};
