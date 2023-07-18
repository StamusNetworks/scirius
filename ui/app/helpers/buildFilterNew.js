import { buildQFilter } from 'ui/buildQFilter';

const buildFilterNew = (filters, systemSettings) => {
  const regularFilters = filters
    .filter(f => f.id !== 'probe' && f.id !== 'alert.tag')
    .reduce((acc, cur) => {
      acc[cur.id] = cur.value;
      return acc;
    }, {});
  const queryFilters = buildQFilter(filters, systemSettings, 'object');
  return { ...regularFilters, ...queryFilters };
};

export default buildFilterNew;
