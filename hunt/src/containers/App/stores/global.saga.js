import * as config from 'hunt_common/config/Api';
import { call, put, takeLatest } from 'redux-saga/effects';

import axios from 'axios';
import { GET_USER_DETAILS_REQUEST, getUserDetailsFailure, getUserDetailsSuccess } from './global';

export function* fetchUserData() {
  const requestURL = `${config.API_URL}${config.USER_PATH}current_user/`;
  try {
    const repos = yield call(axios.get, requestURL);
    const { data = {} } = repos;
    yield put(getUserDetailsSuccess(data));
  } catch (err) {
    yield put(getUserDetailsFailure(err));
  }
}

export default function* root() {
  yield takeLatest(GET_USER_DETAILS_REQUEST, fetchUserData);
}
