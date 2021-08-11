import history from 'utils/history';
import { FiltersMap } from 'ui/maps/FiltersMap';
import { parseUrl } from 'ui/helpers/parseUrl';
import { parseObjectToUrl } from 'ui/helpers/parseObjectToUrl';

export const extendUrlFilters = (filterName, filterValue) => {
  let emit = false;
  const future = { ...history };
  const { filterName: filter = {} } = FiltersMap;
  const { canHaveMultiple } = filter;
  const params = history.location.search.length > 0 ? parseUrl(history.location.search) : [];
  if (canHaveMultiple) {
    if (!params[filterName]) {
      params[filterName] = [];
    }
    if (params[filterName].indexOf(filterValue) === -1) {
      params[filterName].push(filterValue);
      emit = true;
    }
  } else {
    params[filterName] = filterValue;
    emit = true;
  }
  future.location.search = parseObjectToUrl(params);
  if (emit) {
    history.push(future.location);
  }
};
