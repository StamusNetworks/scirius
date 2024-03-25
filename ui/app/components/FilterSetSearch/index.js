import React from 'react';

import { SearchOutlined } from '@ant-design/icons';
import { Input } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const { Search } = Input;

const SearchStyled = styled(Search)`
  margin-bottom: 10px;
  .ant-input-group-addon {
    display: none;
  }
`;

const FilterSetSearch = ({ disabled, value, onChange }) => (
  <div className="input-group">
    <span className="input-group-addon">
      <i className="fa fa-search"></i>
    </span>
    <SearchStyled
      disabled={disabled}
      allowClear
      enterButton={null}
      size="large"
      prefix={<SearchOutlined />}
      placeholder="Search for filter set"
      value={value}
      onChange={event => onChange(event.target.value)}
      data-test="search-filter-set"
    />
  </div>
);

export default FilterSetSearch;

FilterSetSearch.propTypes = {
  disabled: PropTypes.bool.isRequired,
  value: PropTypes.string.isRequired,
  onChange: PropTypes.func.isRequired,
};
