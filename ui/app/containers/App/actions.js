import constants from 'ui/containers/App/constants';

const getUser = () => ({
    type: constants.GET_USER_REQUEST,
  })

const getUserSuccess = (user) => ({
    type: constants.GET_USER_SUCCESS,
    payload: user,
  })

const getUserFailure = () => ({
    type: constants.GET_USER_FAILURE,
  })

const getSettings = () => ({
    type: constants.GET_SETTINGS_REQUEST,
  })

const getSettingsSuccess = (globalSettings, systemSettings) => ({
    type: constants.GET_SETTINGS_SUCCESS,
    payload: {
      globalSettings,
      systemSettings,
    },
  })

const getSettingsFailure = () => ({
    type: constants.GET_SETTINGS_FAILURE,
  })

const getSource = () => ({
    type: constants.GET_SOURCE_REQUEST,
  })

const getSourceSuccess = (source) => ({
    type: constants.GET_SOURCE_SUCCESS,
    payload: {
      source,
    },
  })

const getSourceFailure = () => ({
    type: constants.GET_SOURCE_FAILURE,
  })

const setTimeSpan = (startDate, endDate) => ({
    type: constants.SET_TIME_SPAN,
    startDate,
    endDate,
  })

const setDuration = (duration) => ({
    type: constants.SET_DURATION,
    duration,
  })

const setReload = (reloadPeriod) => ({
    type: constants.SET_RELOAD,
    payload: {
      reloadPeriod,
    },
  })


const doReload = () => ({
    type: constants.DO_RELOAD,
  })

const getAllPeriodRequest = () => ({
    type: constants.GET_PERIOD_ALL_REQUEST,
  })

const getAllPeriodSuccess = (minTimestamp, maxTimestamp) => ({
    type: constants.GET_PERIOD_ALL_SUCCESS,
    payload: {
      minTimestamp,
      maxTimestamp
    }
  })

const getAllPeriodFailure = () => ({
    type: constants.GET_PERIOD_ALL_FAILURE,
  })

export default {
  getUser,
  getUserSuccess,
  getUserFailure,
  getSettings,
  getSettingsSuccess,
  getSettingsFailure,
  getSource,
  getSourceSuccess,
  getSourceFailure,
  setTimeSpan,
  setDuration,
  setReload,
  doReload,
  getAllPeriodRequest,
  getAllPeriodSuccess,
  getAllPeriodFailure,
}
