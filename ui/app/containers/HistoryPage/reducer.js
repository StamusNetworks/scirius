import produce from 'immer';
import { ACTION_TYPES_LOADING, ACTION_TYPES_SUCCESS, ACTION_TYPES_FAIL } from './constants';

export const initialState = {
  actionTypesList: [],
  actionTypesLoading: false,
  actionTypesStatus: false,
  actionTypesMessage: '',
};

/* eslint-disable default-case */
const historyReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case ACTION_TYPES_LOADING:
        draft.actionTypesList = [];
        draft.actionTypesLoading = true;
        draft.actionTypesStatus = false;
        draft.actionTypesMessage = 'loading...';
        break;

      case ACTION_TYPES_SUCCESS: {
        const actionTypeList = Object.keys(action.actionTypesList);
        const actions = [];
        for (let i = 0; i < actionTypeList.length; i += 1) {
          const item = actionTypeList[i];
          actions.push({ id: item, title: action.actionTypesList[item] });
        }
        draft.actionTypesList = actions;
        draft.actionTypesLoading = false;
        draft.actionTypesStatus = true;
        draft.actionTypesMessage = '';
        break;
      }
      case ACTION_TYPES_FAIL:
        draft.actionTypesList = [];
        draft.actionTypesLoading = false;
        draft.actionTypesStatus = false;
        draft.actionTypesMessage = ''; // @TODO: Set proper fail message
        break;
    }
  })



export default historyReducer;
