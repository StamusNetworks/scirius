/**
 * Combine all reducers in this file and export the combined reducers.
 */

import languageProviderReducer from 'containers/LanguageProvider/reducer';
import { combineReducers } from 'redux';

import history from 'utils/history';

/**
 * Merges the main reducer with the router state and dynamically injected reducers
 */
export default function createReducer(injectedReducers = {}) {
  const rootReducer = combineReducers({
    language: languageProviderReducer,
    ...injectedReducers,
  });

  return rootReducer;
}
