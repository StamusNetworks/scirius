import React from 'react';
import PropTypes from 'prop-types';
import { ActionButton } from '../styles';

const SaveFilterSetButton = ({ filters, onClick }) => (
  <ActionButton active={filters.length > 0} data-test="save-filter-set">
    <svg enableBackground="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000">
      <g>
        <rect fill="none" height="24" width="24" />
      </g>
      <g>
        <path d="M14,10H3v2h11V10z M14,6H3v2h11V6z M18,14v-4h-2v4h-4v2h4v4h2v-4h4v-2H18z M3,16h7v-2H3V16z" />
      </g>
    </svg>
    {filters.length > 0 && (
      <a
        onClick={e => {
          e.preventDefault();
          onClick();
        }}
      >
        Save Filter Set
      </a>
    )}
    {filters.length === 0 && <>Save Filter Set</>}
  </ActionButton>
);

export default SaveFilterSetButton;

SaveFilterSetButton.propTypes = {
  onClick: PropTypes.func.isRequired,
  filters: PropTypes.array,
};
