import crcf from 'ui/helpers/crcf';
import request from 'ui/helpers/request';

/**
 * Api interface
 *
 * Usage: Api.get('http://url/', { item: 1 }, { headers: { 'Content-Type': 'application/json' } }),
 *
 * @param endpoint (with url and name properties) $endpoint
 * @param url parameters as key/values object $params
 * @param fetch options key/values object $options
 * @return async fetch instance
 */

const Api = {
  get: async (endpoint, params, options) => request(endpoint, 'GET', params, options),
  post: async (endpoint, params, options) =>
    request(endpoint, 'POST', params, {
      ...crcf(),
      ...options,
    }),
  patch: async (endpoint, params, options) =>
    request(endpoint, 'PATCH', params, {
      ...crcf(),
      ...options,
    }),
  delete: async (endpoint, params, options) =>
    request(endpoint, 'DELETE', params, {
      ...crcf(),
      ...options,
    }),
};

export default Api;
