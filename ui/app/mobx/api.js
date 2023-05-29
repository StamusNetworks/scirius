import { create } from 'apisauce';
import map from 'ui/mobx/map';

const apiInstance = create({
  baseURL: '/',
});

apiInstance.addRequestTransform(request => {
  // Handle path parameters /foo/4/bar
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
    .filter(m => Boolean(map[m]))
    .forEach(match => {
      request.params[match.substring(1)] = map[match];
    });
});

export const api = apiInstance;
