import { fromJS } from 'immutable';
import { ACTION_TYPES_LOADING, ACTION_TYPES_SUCCESS, ACTION_TYPES_FAIL } from './constants';

export const initialState = fromJS({
    actionTypesList: [],
    actionTypesLoading: false,
    actionTypesStatus: false,
    actionTypesMessage: '',
});

function historyReducer(state = initialState, action) {
    switch (action.type) {
        case ACTION_TYPES_LOADING:
            return state
            .set('actionTypesList', fromJS([]))
            .set('actionTypesLoading', true)
            .set('actionTypesStatus', false)
            .set('actionTypesMessage', 'loading...');

        case ACTION_TYPES_SUCCESS: {
            const actionTypeList = Object.keys(action.actionTypesList);
            const actions = [];
            for (let i = 0; i < actionTypeList.length; i += 1) {
                const item = actionTypeList[i];
                actions.push({ id: item, title: action.actionTypesList[item] });
            }
            return state
            .set('actionTypesList', fromJS(actions))
            .set('actionTypesLoading', false)
            .set('actionTypesStatus', true)
            .set('actionTypesMessage', '');
        }
        case ACTION_TYPES_FAIL:
            return state
            .set('actionTypesList', fromJS([]))
            .set('actionTypesLoading', false)
            .set('actionTypesStatus', false)
            .set('actionTypesMessage', ''); // @TODO: Set proper fail message

        default:
            return state;
    }
}

export default historyReducer;
