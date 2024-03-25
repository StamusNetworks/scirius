import { call, put, takeEvery } from 'redux-saga/effects';

import NetworkService from 'ui/services/NetworkService';
import filtersActions from 'ui/stores/filters/actions';

import actions from './actions';
import constants from './constants';

function* postFilterSetData(action) {
  try {
    const response = yield call(NetworkService.saveFilterSet, {}, { body: JSON.stringify(action.payload.data) });
    const { host_id: data = {} } = response;
    yield put(actions.saveFilterSetSuccess(data));
    yield put(filtersActions.huntFilterRequest());
  } catch (e) {
    yield put(actions.saveFilterSetFailure(e));
  }
}

export default function* rootSaga() {
  yield takeEvery(constants.SAVE_FILTER_SET_REQUEST, postFilterSetData);
}
