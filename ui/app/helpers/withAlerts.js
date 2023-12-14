import { cloneDeep } from 'lodash';
import Filter from 'utils/Filter';

const withAlerts = idsFilters => {
  let isEnabled = false;
  try {
    isEnabled = Boolean(JSON.parse(localStorage.getItem('withAlerts')));
  } catch (e) {
    isEnabled = false;
  }

  const filters = cloneDeep(idsFilters);
  if (isEnabled) {
    const i = filters.findIndex(f => f.id === 'hits_min');
    if (i === -1) {
      const hitsMin = new Filter('hits_min', 1);
      filters.push(hitsMin.toJSON());
    }
  }
  return filters;
};

export default withAlerts;
