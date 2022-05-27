import produce from 'immer';
import constants from 'ui/stores/filters/constants';

export const initialState = {
  filterSet: [],
  filterList: [],
  supportedActions: [],
}

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.RULE_SETS_SUCCESS: {
        draft.filterSet = action.payload.data;
        break;
      }
      case constants.RULE_SETS_FAILURE: {
        draft.filterList = [];
        break;
      }
      case constants.HUNT_FILTER_SUCCESS: {
        draft.filterList = action.payload.data;
        break;
      }
      case constants.HUNT_FILTER_FAILURE: {
        draft.filterList = [];
        break;
      }
      case constants.SUPPORTED_ACTIONS_SUCCESS: {
        draft.supportedActions = action.payload.data;
        break;
      }
      case constants.SUPPORTED_ACTIONS_FAILURE: {
        draft.supportedActions = [];
        break;
      }
      case constants.HISTORY_FILTERS_SUCCESS: {
        draft.historyFilters = action.payload.data;
        break;
      }
      case constants.HISTORY_FILTERS_FAILURE: {
        draft.historyFilters = []
        break;
      }
    }
  })

export default appReducer;
