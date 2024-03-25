import React from 'react';

import PropTypes from 'prop-types';
import styled from 'styled-components';

import FilterItem from 'ui/components/FilterItem';
import { useStore } from 'ui/mobx/RootStoreProvider';

const ListInline = styled.ul`
  list-style: none;
  display: flex;
  flex-direction: row;
  flex-wrap: wrap;
  justify-content: flex-start;
  margin: 0;
  margin-block-start: 0;
  margin-block-end: 0;
  padding-inline-start: 0;
`;

const FilterList = props => {
  const { commonStore } = useStore();
  const filters = props.filterTypes.length === 1 && props.filterTypes[0] === 'HISTORY' ? commonStore.history : commonStore.filters;
  return (
    <React.Fragment>
      {/* eslint-disable react/no-array-index-key */}
      <ListInline>
        {filters.map((filter, idx) => (
          <FilterItem key={idx} filter={filter} disabled={!props.filterTypes.some(f => filter.category?.includes(f))} />
        ))}
      </ListInline>
    </React.Fragment>
  );
};

FilterList.propTypes = {
  filterTypes: PropTypes.array,
};

export default FilterList;
