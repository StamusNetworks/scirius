import produce from 'immer';
import constants from 'ui/stores/filters/constants';

export const initialState = {
  filterSet: [],
  filterList: [],
  supportedActions: [],
  historyFilters: [],
  saveFiltersModal: false,
};

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
        const actionTypeList = Object.keys(action.payload.data);
        const actions = [];
        for (let i = 0; i < actionTypeList.length; i += 1) {
          const item = actionTypeList[i];
          actions.push({ id: item, title: action.payload.data[item] });
        }
        draft.filterList = [
          {
            id: 'username',
            title: 'User',
            placeholder: 'Filter by User',
            filterType: 'text',
            queryType: 'all',
          },
          {
            id: 'comment',
            title: 'Comment',
            placeholder: 'Filter by Comment',
            filterType: 'text',
            queryType: 'all',
          },
          {
            id: 'action_type',
            title: 'Action Type',
            placeholder: 'Filter by Action Type',
            filterType: 'select',
            filterValues: actions,
            queryType: 'all',
          },
          {
            id: 'client_ip',
            title: 'Client IP',
            placeholder: 'Filter by Client IP',
            filterType: 'text',
            filterValues: [],
            queryType: 'all',
          },
        ];
        break;
      }
      case constants.HISTORY_FILTERS_FAILURE: {
        draft.historyFilters = [];
        break;
      }
      case constants.MODAL_SAVE_FILTERS: {
        draft.saveFiltersModal = action.payload.value;
        break;
      }
    }
  });

export default appReducer;
