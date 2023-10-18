import React from 'react';
import PropTypes from 'prop-types';
import FilterItem from 'ui/components/FilterItem';
import styled from 'styled-components';

const ListInline = styled.span`
  list-style: none;
  display: inline-block;
  margin: 0;
  margin-block-start: 0;
  margin-block-end: 0;
  padding-inline-start: 0;

  & li {
    box-sizing: border-box;
    color: rgb(65, 64, 66);
    display: inline-block;
    font-family: 'Open Sans', Helvetica, Arial, sans-serif;
    font-size: 12px;
    height: 23.5px;
    line-height: 40px;
    list-style: none outside none;
    padding-left: 5px;
    padding-right: 5px;
    text-align: left;
  }
`;

export const INTERGER_FIELDS_ENDS_WITH = ['.min', '.max', '_min', '_max', '.port', '_port', '.length'];
export const INTERGER_FIELDS_EXACT = [
  'alert.signature_id',
  'alert.rev',
  'alert.severity',
  'http.status',
  'vlan',
  'flow_id',
  'flow.bytes_toclient',
  'flow.bytes_toserver',
  'flow.pkts_toclient',
  'flow.pkts_toserver',
  'geoip.provider.autonomous_system_number',
  'port',
];

const FilterList = props => (
  <React.Fragment>
    {/* eslint-disable react/no-array-index-key */}
    <ListInline>
      {props.filters.map((filter, idx) => (
        <FilterItem key={idx} filterType={props.filterType} filter={filter} disabled={props.page === 'HOST_INSIGHT'} />
      ))}
    </ListInline>
  </React.Fragment>
);

FilterList.propTypes = {
  page: PropTypes.oneOf(['RULES_LIST', 'DASHBOARDS', 'ALERTS_LIST', 'HISTORY', 'HOSTS_LIST', 'HOST_INSIGHT', 'INVENTORY']),
  filters: PropTypes.array,
  filterType: PropTypes.string,
};

export default FilterList;
