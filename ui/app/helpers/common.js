import axios from 'axios';
import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';

export function buildListUrlParams(pageParams) {
  const { page, perPage } = pageParams.pagination;
  const { sort } = pageParams;
  let ordering = '';

  if (sort.asc) {
    ordering = sort.id;
  } else {
    ordering = `-${sort.id}`;
  }

  return `ordering=${ordering}&page_size=${perPage}&page=${page}`;
}

export function loadActions(filtersIn) {
  let { filters } = this.props;
  if (typeof filtersIn !== 'undefined') {
    filters = filtersIn;
  }
  filters = filters.map(f => f.id);
  const reqData = { fields: filters };
  axios.post(`${config.API_URL}${config.PROCESSING_PATH}test_actions/`, reqData).then(res => {
    this.setState({ supported_actions: res.data.actions });
  });
}

/**
 * [DEPRECATED] The building filter parameters.
 * Use buildFilterNew instead
 *
 * @param filters
 * @param systemSettings
 * @returns {string}
 */
export function buildFilter(filters, systemSettings) {
  const lFilters = {};
  for (let i = 0; i < filters.length; i += 1) {
    if (filters[i].id !== 'probe' && filters[i].id !== 'alert.tag') {
      if (filters[i].id in lFilters) {
        lFilters[filters[i].id] += `,${filters[i].value}`;
      } else {
        lFilters[filters[i].id] = filters[i].value;
      }
    }
  }
  let stringFilters = '';
  const objKeys = Object.keys(lFilters);
  for (let k = 0; k < objKeys.length; k += 1) {
    stringFilters += `&${objKeys[k]}=${lFilters[objKeys[k]]}`;
  }
  const qfilter = buildQFilter(filters, systemSettings);
  if (qfilter) {
    stringFilters += qfilter;
  }
  return stringFilters;
}
