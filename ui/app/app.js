/**
 * app.js
 */

// Needed for redux-saga es6 generator support
import '@babel/polyfill';

// Import all the third party stuff
import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import FontFaceObserver from 'fontfaceobserver';
import { SingletonHooksContainer } from 'react-singleton-hook';
import { BrowserRouter } from 'react-router-dom';

import './fonts/fonts.css';

// Import root app
import App from 'ui/containers/App';
import notify from 'ui/helpers/notify';

// Load the favicon and the .htaccess file
import '!file-loader?name=[name].[ext]!./images/favicon.ico';
import axios from 'axios';
import { RootStoreProvider } from 'ui/mobx/RootStoreProvider';
import { store } from './store';

// Observe loading of Open Sans (to remove open sans, remove the <link> tag in
// the index.html file and this observer)
const openSansObserver = new FontFaceObserver('Open Sans', {});

// When Open Sans is loaded, add a font-family using Open Sans to the body
openSansObserver.load().then(() => {
  document.body.classList.add('fontLoaded');
});

const MOUNT_NODE = document.getElementById('app');

axios.interceptors.response.use(
  response => response,
  error => {
    notify('Request has failed', error);
    return Promise.reject(error);
  },
);

const render = () => {
  ReactDOM.render(
    <RootStoreProvider>
      <Provider store={store}>
        <BrowserRouter>
          <App />
          <SingletonHooksContainer />
        </BrowserRouter>
      </Provider>
    </RootStoreProvider>,
    MOUNT_NODE,
  );
};

if (module.hot) {
  // Hot reloadable React components and translation json files
  // modules.hot.accept does not accept dynamic dependencies,
  // have to be constants at compile-time
  // 2 apps in one React app, hence two entry points to watch
  try {
    module.hot.accept(['appliance/containers/App'], () => {
      ReactDOM.unmountComponentAtNode(MOUNT_NODE);
      render();
    });
  } catch (e) {
    module.hot.accept(['containers/App'], () => {
      ReactDOM.unmountComponentAtNode(MOUNT_NODE);
      render();
    });
  }
}

render();
