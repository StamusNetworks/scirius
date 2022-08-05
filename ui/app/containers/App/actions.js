import constants from 'ui/containers/App/constants';

const getUser = () => ({
  type: constants.GET_USER_REQUEST,
});

const getUserSuccess = user => ({
  type: constants.GET_USER_SUCCESS,
  payload: user,
});

const getUserFailure = () => ({
  type: constants.GET_USER_FAILURE,
});

const getSource = () => ({
  type: constants.GET_SOURCE_REQUEST,
});

const getSourceSuccess = source => ({
  type: constants.GET_SOURCE_SUCCESS,
  payload: {
    source,
  },
});

const getSourceFailure = () => ({
  type: constants.GET_SOURCE_FAILURE,
});

const setTimeSpan = (startDate, endDate) => ({
  type: constants.SET_TIME_SPAN,
  startDate,
  endDate,
});

const setDuration = duration => ({
  type: constants.SET_DURATION,
  duration,
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

export default {
  getUser,
  getUserSuccess,
  getUserFailure,
  getSource,
  getSourceSuccess,
  getSourceFailure,
  setTimeSpan,
  setDuration,
  setReload,
  setFilterSets,
  doReload,
  getAllPeriodRequest,
  getAllPeriodSuccess,
  getAllPeriodFailure,
  setSessionActivityRequest,
  setSessionActivityFailure,
};
