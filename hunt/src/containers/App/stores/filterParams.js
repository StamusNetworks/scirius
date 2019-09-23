import { fromJS } from 'immutable';
import { createSelector } from 'reselect';
import { defaultFilterParams } from 'hunt_common/stores/filterParamsDefault';

export const FILTER_PARAMS_SET = 'Hunt/App/FILTER_PARAM_SET';

export function filterParamsSet(paramName, paramValue) {
    return {
        type: FILTER_PARAMS_SET,
        paramName,
        paramValue
    };
}

const initialState = fromJS(defaultFilterParams);

export const reducer = (state = initialState, action) => {
    switch (action.type) {
        case FILTER_PARAMS_SET:
            return state.setIn([action.paramName], action.paramValue);

        default:
            return state;
    }
}

export const selectFilterParamsStore = (state) => state.get('filterParams', initialState);
export const makeSelectFilterParam = (paramName) => createSelector(selectFilterParamsStore, (globalState) => globalState.getIn([paramName]));
export const makeSelectFilterParams = () => createSelector(selectFilterParamsStore, (globalState) => globalState.toJS());
