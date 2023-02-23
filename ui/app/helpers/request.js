import notify from 'ui/helpers/notify';
import translateUrl from 'ui/helpers/translateUrl';

const request = async (endpoint, method, params, options) => {
  const fullPath = translateUrl(endpoint.url, params);
  const log = [];
  try {
    log.push([`[REQ] [${method}] ${fullPath}`]);
    const response = await fetch(fullPath, {
      ...options,
      method,
      credentials: 'same-origin', // force sending cookie on older browsers
    });

    if (response.status === 404 || (response.status >= 200 && response.status < 300)) {
      if (response.status === 204 || response.status === 205) {
        log.push([`[RES] [${response.status}]:`, {}]);
        return {};
      }
      const json = await response.json();
      log.push([`[RES] [${response.status}]:`, json]);
      return json;
    }
    const error = new Error(response.statusText);
    error.response = response;
    throw error;
  } catch (error) {
    log.push([`%c[RES] Request has failed \n ${error.message}`, 'color: #CC0000']);
    notify(`${endpoint.name} has failed`, error);
    throw error;
  } finally {
    // if (process.env.NODE_ENV === 'development') {
    //   // eslint-disable-next-line no-console
    //   console.group(`%c${endpoint.name}`, 'color: #0088ff');
    //   for (let i = 0; i < log.length; i += 1) {
    //     // eslint-disable-next-line no-console
    //     console.log(...log[i]);
    //   }
    //   // eslint-disable-next-line no-console
    //   console.groupEnd();
    // }
  }
};

export default request;
