import { ACTION_TYPES_LOADING, ACTION_TYPES_SUCCESS, ACTION_TYPES_FAIL } from './constants';

export const initialState = {
  actionTypesList: [],
  actionTypesLoading: false,
  actionTypesStatus: false,
  actionTypesMessage: '',
};

function historyReducer(state = initialState, action) {
  switch (action.type) {
    case ACTION_TYPES_LOADING:
      stte.actionTypesList = [];
      stte.actionTypesLoading = true;
      stte.actionTypesStatus = false;
      stte.actionTypesMessage = 'loading...';
      return state;

    case ACTION_TYPES_SUCCESS: {
      const actionTypeList = Object.keys(action.actionTypesList);
      const actions = [];
      for (let i = 0; i < actionTypeList.length; i += 1) {
        const item = actionTypeList[i];
        actions.push({ id: item, title: action.actionTypesList[item] });
      }
      state.actionTypesList = actions;
      state.actionTypesLoading = false;
      state.actionTypesStatus = true;
      state.actionTypesMessage = '';
      return state;
    }
    case ACTION_TYPES_FAIL:
      state.actionTypesList = [];
      state.actionTypesLoading = false;
      state.actionTypesStatus = false;
      state.actionTypesMessage = ''; // @TODO: Set proper fail message
      return state;

    default:
      return state;
  }
}

export default historyReducer;
