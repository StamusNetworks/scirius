import constants from 'ui/containers/App/constants';

const setTimeSpan = (startDate, endDate) => ({
  type: constants.SET_TIME_SPAN,
  startDate,
  endDate,
});

const setReload = reloadPeriod => ({
  type: constants.SET_RELOAD,
  payload: {
    reloadPeriod,
  },
});

const setFilterSets = value => ({
  type: constants.SET_FILTER_SETS,
  payload: value,
});

const doReload = () => ({
  type: constants.DO_RELOAD,
});

const getAllPeriodRequest = () => ({
  type: constants.GET_PERIOD_ALL_REQUEST,
});

const getAllPeriodSuccess = (minTimestamp, maxTimestamp) => ({
  type: constants.GET_PERIOD_ALL_SUCCESS,
  payload: {
    minTimestamp,
    maxTimestamp,
  },
});

const getAllPeriodFailure = () => ({
  type: constants.GET_PERIOD_ALL_FAILURE,
});

const setSessionActivityRequest = idle => ({
  type: constants.SET_SESSION_ACTIVITY_REQUEST,
  payload: {
    timeout: idle,
  },
});

const setSessionActivityFailure = () => ({
  type: constants.SET_SESSION_ACTIVITY_FAILURE,
});

const updatePushRulesetReset = () => ({
  type: constants.UPDATE_PUSH_RULESET_RESET,
});

const updatePushRulesetRequest = () => ({
  type: constants.UPDATE_PUSH_RULESET_REQUEST,
});

const updatePushRulesetSuccess = () => ({
  type: constants.UPDATE_PUSH_RULESET_SUCCESS,
});

const updatePushRulesetFailure = () => ({
  type: constants.UPDATE_PUSH_RULESET_FAILURE,
});

export default {
  setTimeSpan,
  setReload,
  setFilterSets,
  doReload,
  getAllPeriodRequest,
  getAllPeriodSuccess,
  getAllPeriodFailure,
  setSessionActivityRequest,
  setSessionActivityFailure,
  updatePushRulesetReset,
  updatePushRulesetRequest,
  updatePushRulesetSuccess,
  updatePushRulesetFailure,
};
