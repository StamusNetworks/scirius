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

export const reducer = (state = initialState, action) => {
  switch (action.type) {
    case FILTER_PARAMS_SET: {
      state[action.paramName] = action.paramValue;
      return state;
    }

    case FILTER_TIMESPAN_SET: {
      state.fromDate = action.timeSpan.fromDate;
      state.toDate = action.timeSpan.toDate;
      state.absolute = typeof action.timeSpan.absolute !== 'undefined' ? action.timeSpan.absolute : absolute;
      state.duration = null;
      return state;
    }

    case FILTER_DURATION_SET: {
      state.duration = action.duration;
      state.fromDate = Date.now() - action.duration;
      state.toDate = Date.now();
      state.absolute = absolute;
      return state;
    }

    case TIMESTAMP_RELOAD: {
      if (state.duration) {
        state.fromDate = Math.round(Date.now() - state.duration)
        state.toDate = Date.now();
      } // else absolute/relative no refresh
      return state;
    }

    default:
      return state;
  }
};

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
