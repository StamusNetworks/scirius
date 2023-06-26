/* eslint-disable */
import { takeEvery, put, call } from 'redux-saga/effects';
import { LOGIN_PATH } from 'ui/config/index';
import constants from 'ui/containers/App/constants';
import actions from 'ui/containers/App/actions';
import NetworkService from 'ui/services/NetworkService';

function* retrieveContext() {
  try {
    const data = yield call(NetworkService.fetchContext);
    yield put(actions.getContextSuccess(data));
  } catch (e) {
    yield put(actions.getContextFailure(e));
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
    if (e.response.status === 403) {
      window.location = LOGIN_PATH;
    } else {
      yield put(actions.setSessionActivityFailure());
    }
  }
}

function* retrieveSystemSettings() {
  try {
    // Get system settings
    const systemSettings = yield call(NetworkService.fetchSystemSettings);
    yield put(actions.getSystemSettingsSuccess(systemSettings));
  } catch (err) {
    yield put(actions.getSystemSettingsFailure());
  }
}

function* updatePushRuleset() {
  try {
    yield call(NetworkService.updatePushRuleset);
    yield put(actions.updatePushRulesetSuccess());
  } catch (err) {
    yield put(actions.updatePushRulesetFailure());
  }
}

export default function* rootSage() {
  yield takeEvery(constants.GET_SYSTEM_SETTINGS_REQUEST, retrieveSystemSettings);
  yield takeEvery(constants.GET_CONTEXT_REQUEST, retrieveContext);
  yield takeEvery(constants.GET_SOURCE_REQUEST, getSources);
  yield takeEvery(constants.GET_PERIOD_ALL_REQUEST, getAllPeriod);
  yield takeEvery(constants.SET_SESSION_ACTIVITY_REQUEST, setSessionActivity);
  yield takeEvery(constants.UPDATE_PUSH_RULESET_REQUEST, updatePushRuleset);
}
