/**
 * Gets the repositories of the user from Github
 */

import { takeEvery, put, call } from 'redux-saga/effects';
import request from 'utils/request';
import { API_URL, CURRENT_USER_PATH } from 'ui/config';
import { getResponseAsText } from 'ui/helpers/getResponseAsText';
import { throwAs } from 'ui/helpers/throwAs';
import constants from 'ui/containers/App/constants';
import actions from 'ui/containers/App/actions';

function* retrieveUser() {
  try {
    // Call our request helper (see 'utils/request')
    const user = yield call(request, `${CURRENT_USER_PATH}`);
    yield put(actions.getUserSuccess(user));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(actions.getUserFailure(err.response.status, err, errorText));
  }
}

function* retrieveGlobalSettings() {
  try {
    const data = yield call(request, `${API_URL}/global_settings`);
    yield put(actions.getGlobalSettingsSuccess(data));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(actions.getGlobalSettingsFailure(err.response.status, err, errorText));
  }
}

function* getSources() {
  try {
    const data = yield call(request, `/rest/rules/source/?datatype=threat`);
    const { results = [] } = data;
    yield put(actions.getSourceSuccess(results));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(actions.deleteThreatFailure(err.response.status, err, errorText));
  }
}

export default function* rootSage() {
  yield takeEvery(constants.GET_USER_REQUEST, retrieveUser);
  yield takeEvery(constants.GET_GLOBAL_SETTINGS_REQUEST, retrieveGlobalSettings);
  yield takeEvery(constants.GET_SOURCE_REQUEST, getSources);
}
