import constants from 'ui/containers/App/constants';

const getUser = () => ({
    type: constants.GET_USER_REQUEST,
  })

const getUserSuccess = (user) => ({
    type: constants.GET_USER_SUCCESS,
    payload: user,
  })

const getUserFailure = (httpCode, httpError, httpResponse) => ({
    type: constants.GET_USER_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
  })

const getGlobalSettings = () => ({
    type: constants.GET_GLOBAL_SETTINGS_REQUEST,
  })

const getGlobalSettingsSuccess = (data) => ({
    type: constants.GET_GLOBAL_SETTINGS_SUCCESS,
    payload: {
      data,
    },
  })

const getGlobalSettingsFailure = (httpCode, httpError, httpResponse) => ({
    type: constants.GET_GLOBAL_SETTINGS_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
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

const getSourceFailure = (httpCode, httpError, httpResponse) => ({
    type: constants.GET_SOURCE_FAILURE,
    payload: {
      httpCode,
      httpError,
      httpResponse,
    },
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

export default {
  getUser,
  getUserSuccess,
  getUserFailure,
  getGlobalSettings,
  getGlobalSettingsSuccess,
  getGlobalSettingsFailure,
  getSource,
  getSourceSuccess,
  getSourceFailure,
  setTimeSpan,
  setDuration,
  setReload,
  doReload,
}
