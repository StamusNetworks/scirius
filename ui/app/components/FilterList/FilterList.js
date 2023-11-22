import React from 'react';
import PropTypes from 'prop-types';
import FilterItem from 'ui/components/FilterItem';
import styled from 'styled-components';

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

const FilterList = props => (
  <React.Fragment>
    {/* eslint-disable react/no-array-index-key */}
    <ListInline>
      {props.filters.map((filter, idx) => (
        <FilterItem key={idx} filter={filter} disabled={!props.filterTypes.some(f => f === filter.category || filter.category.includes(f))} />
      ))}
    </ListInline>
  </React.Fragment>
);

FilterList.propTypes = {
  filters: PropTypes.array,
  filterTypes: PropTypes.array,
};

export default FilterList;
