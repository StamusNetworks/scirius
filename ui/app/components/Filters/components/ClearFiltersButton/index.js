import React from 'react';
import { CloseOutlined } from '@ant-design/icons';
import PropTypes from 'prop-types';
import { useStore } from 'ui/mobx/RootStoreProvider';
import { ActionButton } from '../styles';

const ClearFiltersButton = ({ onClick }) => {
  const { commonStore } = useStore();
  return (
    <ActionButton active={commonStore.getFilters().length > 0}>
      <CloseOutlined style={{ width: 24 }} />
      {commonStore.getFilters().length > 0 && (
        <a
          onClick={e => {
            e.preventDefault();
            onClick();
          }}
          data-test="clear-filters"
        >
          Clear Filters
        </a>
      )}
      {commonStore.getFilters().length === 0 && <>Clear Filters</>}
    </ActionButton>
  );
};

export default ClearFiltersButton;

ClearFiltersButton.propTypes = {
  onClick: PropTypes.func.isRequired,
};
