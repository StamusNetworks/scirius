/**
 * Gets the repositories of the user from Github
 */

import { takeEvery, put, call, select } from 'redux-saga/effects';
import request from 'utils/request';
import cookie from 'cookie';
import { API_URL, CURRENT_USER_PATH } from 'ui/config';
import { getResponseAsText } from 'ui/helpers/getResponseAsText';
import { throwAs } from 'ui/helpers/throwAs';
import {
  DELETE_THREAT_REQUEST,
  GET_ACTIVE_FAMILIES_REQUEST,
  GET_ACTIVE_THREATS_REQUEST,
  GET_FAMILIES_REQUEST,
  GET_GLOBAL_SETTINGS_REQUEST,
  GET_SOURCE_REQUEST,
  GET_TENANTS_REQUEST,
  GET_THREATS_REQUEST,
  GET_USER_REQUEST,
} from './constants';
import {
  deleteThreatFailure,
  deleteThreatSuccess,
  getActiveFamiliesFailure,
  getActiveFamiliesSuccess,
  getActiveThreatsFailure,
  getActiveThreatsSuccess,
  getFamiliesFail,
  getFamiliesSuccess,
  getGlobalSettingsFailure,
  getGlobalSettingsSuccess,
  getSourceSuccess,
  getTenantsFailure,
  getTenantsSuccess,
  getUserSuccess,
  getUserFailure,
  getThreatsFailure,
  getThreatsSuccess,
} from './actions';
import { makeSelectEndDate, makeSelectFiltersParam, makeSelectStartDate, makeSelectTenantParam } from './selectors';

export function* retrieveAllFamilies() {
  try {
    // Call our request helper (see 'utils/request')
    const families = yield call(request, `${API_URL}/threat_family/?event_view=false`);
    const { results = [] } = families;
    yield put(getFamiliesSuccess(results));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getFamiliesFail(err.response.status, err, errorText));
  }
}

export function* retrieveActiveFamilies() {
  try {
    const startDate = yield select(makeSelectStartDate());
    const endDate = yield select(makeSelectEndDate());
    const filtersParam = yield select(makeSelectFiltersParam('&'));
    const families = yield call(
      request,
      `${API_URL}/threat_family/top_list/?start_date=${startDate.unix()}&end_date=${endDate.unix()}${filtersParam}`,
    );
    yield put(getActiveFamiliesSuccess(families));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getActiveFamiliesFailure(err.response.status, err, errorText));
  }
}

export function* retrieveUser() {
  try {
    // Call our request helper (see 'utils/request')
    const user = yield call(request, `${CURRENT_USER_PATH}`);
    yield put(getUserSuccess(user));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getUserFailure(err.response.status, err, errorText));
  }
}

export function* retrieveAllThreats() {
  try {
    // Call our request helper (see 'utils/request')
    const tenantParam = yield select(makeSelectTenantParam());
    const response = yield call(request, `${API_URL}/threat/?page_size=10000&event_view=false${tenantParam}`);
    const { results = [] } = response;
    yield put(getThreatsSuccess(results));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getThreatsFailure(err.response.status, err, errorText));
  }
}

export function* retrieveActiveThreats(action) {
  const { familyId } = action.payload;
  try {
    const startDate = yield select(makeSelectStartDate());
    const endDate = yield select(makeSelectEndDate());
    const filtersParam = yield select(makeSelectFiltersParam());
    let threats = yield call(
      request,
      `${API_URL}/threat/top_list/?family_id=${familyId}&start_date=${startDate.unix()}&end_date=${endDate.unix()}${filtersParam}`,
    );
    const { detail = '' } = threats;
    threats = detail === 'Not found.' ? [] : threats;
    yield put(getActiveThreatsSuccess(familyId, threats));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getActiveThreatsFailure(err.response.status, err, errorText, familyId));
  }
}

export function* retrieveGlobalSettings() {
  try {
    const data = yield call(request, `${API_URL}/global_settings`);
    yield put(getGlobalSettingsSuccess(data));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getGlobalSettingsFailure(err.response.status, err, errorText));
  }
}

export function* retrieveTenants() {
  try {
    const tenants = yield call(request, `${API_URL}/network_definition?page_size=500`);
    const { results = [] } = tenants;
    yield put(getTenantsSuccess(results));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(getTenantsFailure(err.response.status, err, errorText));
  }
}

export function* deleteThreat(action) {
  const { threatId } = action.payload;
  try {
    const cookies = cookie.parse(document.cookie);
    yield call(request, `${API_URL}/threat/${threatId}/?event_view=false`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': cookies.csrftoken,
      },
    });
    yield put(deleteThreatSuccess(threatId));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(deleteThreatFailure(err.response.status, err, errorText));
  }
}

export function* getSources() {
  try {
    const data = yield call(request, `/rest/rules/source/?datatype=threat`);
    const { results = [] } = data;
    yield put(getSourceSuccess(results));
  } catch (err) {
    const errorText = yield getResponseAsText(err.response);
    throwAs('error', errorText);
    yield put(deleteThreatFailure(err.response.status, err, errorText));
  }
}

/**
 * Root saga manages watcher lifecycle
 */
export default function* rootSage() {
  // Watches for LOAD_REPOS actions and calls getRepos when one comes in.
  // By using `takeLatest` only the result of the latest API call is applied.
  // It returns task descriptor (just like fork) so we can continue execution
  // It will be cancelled automatically on component unmount
  yield takeEvery(GET_FAMILIES_REQUEST, retrieveAllFamilies);
  yield takeEvery(GET_USER_REQUEST, retrieveUser);
  yield takeEvery(GET_THREATS_REQUEST, retrieveAllThreats);
  yield takeEvery(GET_ACTIVE_THREATS_REQUEST, retrieveActiveThreats);
  yield takeEvery(GET_ACTIVE_FAMILIES_REQUEST, retrieveActiveFamilies);
  yield takeEvery(GET_GLOBAL_SETTINGS_REQUEST, retrieveGlobalSettings);
  yield takeEvery(GET_TENANTS_REQUEST, retrieveTenants);
  yield takeEvery(DELETE_THREAT_REQUEST, deleteThreat);
  yield takeEvery(GET_SOURCE_REQUEST, getSources);
}
