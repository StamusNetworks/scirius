/*
 * AppReducer
 *
 */

import produce from 'immer';

import { LOCATION_CHANGE } from './constants';

// The initial state of the App
export const initialState = {
};

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case LOCATION_CHANGE: {
        break;
      }
    }
  });

export default appReducer;
