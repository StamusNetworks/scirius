/**
 * Combine all reducers in this file and export the combined reducers.
 */

import { combineReducers } from 'redux';

import globalReducer from 'ui/containers/App/reducer';
import { reducer as huntReducer } from 'ui/containers/HuntApp/stores/global';

/**
 * Merges the main reducer with the router state and dynamically injected reducers
 */
export default function createReducer(injectedReducers = {}) {
  const rootReducer = combineReducers({
    global: globalReducer,
    hunt: huntReducer,
    ...injectedReducers,
  });

  return rootReducer;
}
