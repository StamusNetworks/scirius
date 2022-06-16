import { takeEvery, put, call } from 'redux-saga/effects';
import { LOGIN_PATH } from 'ui/config/index';
import constants from 'ui/containers/App/constants';
import actions from 'ui/containers/App/actions';
import NetworkService from 'ui/services/NetworkService';

function* retrieveUser() {
  try {
    // Call our request helper (see 'utils/request')
    const user = yield call(NetworkService.fetchUser);
    yield put(actions.getUserSuccess(user));
  } catch (err) {
    yield put(actions.getUserFailure());
  }
}

function* retrieveSettings() {
  try {
    // Get global settings
    const globalSettings = yield call(NetworkService.fetchGlobalSettings);
    // Get system settings
    const systemSettings = yield call(NetworkService.fetchSystemSettings);

    yield put(actions.getSettingsSuccess(globalSettings, systemSettings));
  } catch (err) {
    yield put(actions.getSettingsFailure());
  }
}

function* getSources() {
  try {
    const data = yield call(NetworkService.fetchSources, { datatype: 'threat' });
    const { results = [] } = data;
    yield put(actions.getSourceSuccess(results));
  } catch (err) {
    yield put(actions.getSourceFailure());
  }
}

function* getAllPeriod() {
  try {
    const timeRange = yield call(NetworkService.fetchAllPeriod, { event: false });
    const { max_timestamp: maxTimestamp = 0, min_timestamp: minTimestamp = 0 } = timeRange;
    yield put(actions.getAllPeriodSuccess(minTimestamp, maxTimestamp));
  } catch (e) {
    yield put(actions.getAllPeriodFailure());
  }
}

function* setSessionActivity(action) {
  const { timeout } = action.payload;
  try {
    const data = yield call(NetworkService.setSessionActivity, {}, { body: JSON.stringify({ timeout }) });
    if (data.disconnect) {
      window.location = LOGIN_PATH;
    }
  } catch (e) {
    yield put(actions.setSessionActivityFailure());
  }
}

export default function* rootSage() {
  yield takeEvery(constants.GET_USER_REQUEST, retrieveUser);
  yield takeEvery(constants.GET_SETTINGS_REQUEST, retrieveSettings);
  yield takeEvery(constants.GET_SOURCE_REQUEST, getSources);
  yield takeEvery(constants.GET_PERIOD_ALL_REQUEST, getAllPeriod);
  yield takeEvery(constants.SET_SESSION_ACTIVITY_REQUEST, setSessionActivity);
}
