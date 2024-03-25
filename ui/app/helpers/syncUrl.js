import { getQueryObject } from './getQueryObject';
import { parseObjectToUrl } from './parseObjectToUrl';

export const syncUrl = () => {
  const { protocol, host, pathname } = window.location;
  const queryObject = getQueryObject();
  const queryString = parseObjectToUrl(queryObject);
  if (queryString.length > 0) {
    const url = `${protocol}//${host}${pathname}?${queryString}`;
    window.history.pushState({ path: url }, '', url);
  }
};
