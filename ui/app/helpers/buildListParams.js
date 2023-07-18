/*
 * this function does sanity checks for the object retrieved from local localStorage
 */
const buildListParams = (params, def) => {
  params = params ?? {};

  if (!params?.pagination) {
    params.pagination = {};
  }
  if (!params?.pagination?.page) {
    params.pagination.page = def?.pagination?.page || 1;
  }
  if (!params?.pagination?.perPage) {
    params.pagination.perPage = def?.pagination?.perPage || 6;
  }
  if (!params?.pagination?.perPageOptions) {
    params.pagination.perPageOptions = def?.pagination?.perPageOptions || [10, 20, 50, 100];
  }
  /* eslint-disable camelcase */
  if (!params?.sort) {
    params.sort = def?.sort || {};
  }
  if (!params?.sort?.id) {
    params.sort.id = def?.sort?.id || 'created';
  }
  if (!params?.sort?.id) {
    params.sort.asc = def?.params?.sort?.id || false;
  }
  return params;
};

export default buildListParams;
