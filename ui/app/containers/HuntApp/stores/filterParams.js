import produce from 'immer';
import moment from 'moment';
import { default as globalSelectors } from 'ui/containers/App/selectors';
import { createSelector } from 'reselect';

export const FILTER_PARAMS_SET = 'Hunt/HuntApp/FILTER_PARAM_SET';
export const FILTER_TIMESPAN_SET = 'Hunt/HuntApp/FILTER_TIMESPAN_SET';
export const FILTER_DURATION_SET = 'Hunt/HuntApp/FILTER_DURATION_SET';
export const TIMESTAMP_RELOAD = 'Hunt/HuntApp/TIMESTAMP_RELOAD';

export function filterParamsSet(paramName, paramValue) {
  return {
    type: FILTER_PARAMS_SET,
    paramName,
    paramValue,
  };
}

export function filterTimeSpanSet(timeSpan) {
  return {
    type: FILTER_TIMESPAN_SET,
    timeSpan,
  };
}

export function filterDurationSet(duration) {
  return {
    type: FILTER_DURATION_SET,
    duration,
  };
}
export function reload() {
  return {
    type: TIMESTAMP_RELOAD,
  };
}

const initialState = {};

export const absolute = {
  from: {
    id: 0,
    value: 0,
    time: moment(),
    now: false,
  },
  to: {
    id: 0,
    value: 0,
    time: moment(),
    now: false,
  },
};

/* eslint-disable default-case */
export const reducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case FILTER_PARAMS_SET: {
        draft[action.paramName] = action.paramValue;
        break;
      }

      case FILTER_TIMESPAN_SET: {
        draft.fromDate = action.timeSpan.fromDate;
        draft.toDate = action.timeSpan.toDate;
        draft.absolute = typeof action.timeSpan.absolute !== 'undefined' ? action.timeSpan.absolute : absolute;
        draft.duration = null;
        break;
      }

      case FILTER_DURATION_SET: {
        draft.duration = action.duration;
        draft.fromDate = Date.now() - action.duration;
        draft.toDate = Date.now();
        draft.absolute = absolute;
        break;
      }

      case TIMESTAMP_RELOAD: {
        if (draft.duration) {
          draft.fromDate = Math.round(Date.now() - state.duration)
          draft.toDate = Date.now();
        } // else absolute/relative no refresh
        break;
      }
    }
  });


export const selectFilterParamsStore = (state) => state.filterParams || {};
export const makeSelectFilterParam = (paramName) => createSelector(selectFilterParamsStore, (globalState) => globalState[paramName]);
export const makeSelectFilterAbsolute = () => createSelector(selectFilterParamsStore, (globalState) => globalState.absolute);
export const makeSelectFilterParams = () => createSelector([globalSelectors.makeSelectStartDate(), globalSelectors.makeSelectEndDate()], (startDate, endDate) => {
  return {
    fromDate: startDate.unix() * 1000.0,
    toDate: endDate.unix() * 1000.0,
    duration: 0
  };
});
