import store from 'store';
import { isEqual, isEmpty } from 'lodash';
import { parseUrl } from 'ui/helpers/parseUrl';
import { StorageEnum } from 'ui/maps/StorageEnum';

export const getQueryObject = () => {
  const currentUrlObject = parseUrl();
  const existingStorageFilters = store.get(StorageEnum.FILTERS);
  if (isEmpty(currentUrlObject) && !isEmpty(existingStorageFilters)) {
    return existingStorageFilters;
  }
  return !isEqual(currentUrlObject, existingStorageFilters) ? currentUrlObject : existingStorageFilters;
};
