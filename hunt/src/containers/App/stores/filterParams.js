import { fromJS } from 'immutable';
import { createSelector } from 'reselect';
import store from 'store';
import { absolute, defaultFilterParams } from 'hunt_common/stores/filterParamsDefault';

export const FILTER_PARAMS_SET = 'Hunt/App/FILTER_PARAM_SET';
export const FILTER_TIMESPAN_SET = 'Hunt/App/FILTER_TIMESPAN_SET';
export const FILTER_DURATION_SET = 'Hunt/App/FILTER_DURATION_SET';
export const TIMESTAMP_RELOAD = 'Hunt/App/TIMESTAMP_RELOAD';

export function filterParamsSet(paramName, paramValue) {
    return {
        type: FILTER_PARAMS_SET,
        paramName,
        paramValue
    };
}

export function filterTimeSpanSet(timeSpan) {
    return {
        type: FILTER_TIMESPAN_SET,
        timeSpan
    };
}

export function filterDurationSet(duration) {
    return {
        type: FILTER_DURATION_SET,
        duration
    };
}
export function reload() {
    return {
        type: TIMESTAMP_RELOAD,
    };
}

const initialState = fromJS(defaultFilterParams);

export const reducer = (state = initialState, action) => {
    switch (action.type) {
        case FILTER_PARAMS_SET: {
            const param = state.setIn([action.paramName], action.paramValue);
            store.set(`filterParams.${action.paramName}`, action.paramValue);
            return param;
        }

        case FILTER_TIMESPAN_SET: {
            const timespan = state
            .set('fromDate', action.timeSpan.fromDate)
            .set('toDate', action.timeSpan.toDate)
            .set('absolute', fromJS((typeof action.timeSpan.absolute !== 'undefined') ? action.timeSpan.absolute : absolute))
            .set('duration', null);
            store.set('timespan', timespan.toJS());
            return timespan;
        }

        case FILTER_DURATION_SET: {
            const timespan = state
            .set('duration', action.duration)
            .set('fromDate', Date.now() - action.duration)
            .set('toDate', Date.now())
            .set('absolute', fromJS(absolute));
            store.set('timespan', timespan.toJS());
            return timespan;
        }

        case TIMESTAMP_RELOAD: {
            if (state.get('duration')) {
                const timespan = state
                .set('fromDate', Math.round(Date.now() - state.get('duration')))
                .set('toDate', Date.now());
                store.set('timespan', timespan.toJS());
                return timespan;
            } // else absolute/relative no refresh
            return state;
        }

        default:
            return state;
    }
}

export const selectFilterParamsStore = (state) => state.get('filterParams', initialState);
export const makeSelectFilterParam = (paramName) => createSelector(selectFilterParamsStore, (globalState) => globalState.getIn([paramName]));
export const makeSelectFilterAbsolute = () => createSelector(selectFilterParamsStore, (globalState) => globalState.get('absolute').toJS());
export const makeSelectFilterParams = () => createSelector(selectFilterParamsStore, (globalState) => globalState.toJS());
