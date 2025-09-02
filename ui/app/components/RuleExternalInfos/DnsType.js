import React from 'react';

import PropTypes from 'prop-types';

import HuntStat from 'ui/HuntStat';

const DnsType = ({ filters, filterParams, loadMore, filterKey }) => (
  <HuntStat title="Type" filters={filters} item={filterKey ?? 'dns.queries.rrtype'} filterParams={filterParams} loadMore={loadMore} />
);

DnsType.propTypes = {
  filters: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  loadMore: PropTypes.func,
  filterKey: PropTypes.string,
};

export default DnsType;
