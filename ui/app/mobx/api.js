import { create } from 'apisauce';
import { cloneDeep } from 'lodash';
import map from 'ui/mobx/map';

const apiInstance = create({
  baseURL: '/',
});

const getCookie = name => {
  const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
  if (match) return match[2];
  return null;
};

apiInstance.addRequestTransform(request => {
  // Handle path parameters /foo/4/bar
  if (request.method === 'patch') {
    request.params = request.data;
    request.data = cloneDeep(request.data.body);
    delete request.params.body;
  }
  if (['patch', 'delete'].includes(request.method)) {
    request.headers['X-Csrftoken'] = getCookie('csrftoken');
  }

  let result = request.url.slice(); // Copy string by value
  const parameters = Object.entries(request.params);
  for (let i = 0; i < parameters.length; i += 1) {
    const [param, value] = parameters[i];
    if (request.url.includes(`$${param}`)) {
      result = result.replace(`$${param}`, value);
      delete request.params[param];
    }
  }

  // Handle URL parameters ?foo=bar&foo2=baz
  const paramRegex = RegExp(':[a-zA-Z]+', 'g');
  const urlParams = result.match(paramRegex) || [];
  request.url = result.replace(paramRegex, ''); // Clean params placeholders

  urlParams
    .filter(m => Boolean(map(m)))
    .forEach(match => {
      request.params = { ...request.params, ...map(match) };
    });
});

export const api = apiInstance;
