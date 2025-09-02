import React from 'react';

import PropTypes from 'prop-types';

import HuntStat from 'ui/HuntStat';

const DnsName = ({ filters, filterParams, loadMore, filterKey }) => (
  <HuntStat title="Name" filters={filters} item={filterKey ?? 'dns.queries.rrname'} filterParams={filterParams} loadMore={loadMore} />
);

DnsName.propTypes = {
  filters: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  loadMore: PropTypes.func,
  filterKey: PropTypes.string,
};

export default DnsName;
