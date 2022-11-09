import React from 'react';
import { CloseOutlined } from '@ant-design/icons';
import PropTypes from 'prop-types';
import { ActionButton } from '../styles';

const ClearFiltersButton = ({ filters, onClick }) => (
  <ActionButton>
    <CloseOutlined style={{ width: 24 }} />
    {filters.length > 0 && (
      <a
        onClick={e => {
          e.preventDefault();
          onClick();
        }}
      >
        Clear Filters
      </a>
    )}
    {filters.length === 0 && <>Clear Filters</>}
  </ActionButton>
);

export default ClearFiltersButton;

ClearFiltersButton.propTypes = {
  filters: PropTypes.array,
  onClick: PropTypes.func.isRequired,
};
