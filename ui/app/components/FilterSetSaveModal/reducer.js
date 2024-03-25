import produce from 'immer';

import constants from './constants';

export const initialState = {
  request: { loading: false, status: null, error: {} },
};

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.SAVE_FILTER_SET_REQUEST: {
        draft.request = { loading: true, status: null };
        break;
      }
      case constants.SAVE_FILTER_SET_SUCCESS: {
        draft.request = { loading: false, status: true };
        break;
      }
      case constants.SAVE_FILTER_SET_FAILURE: {
        draft.request = { loading: false, status: false, error: action.payload };
        break;
      }
    }
  });

export default appReducer;
