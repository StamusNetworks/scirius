import { call, put, takeLatest } from 'redux-saga/effects';

import NetworkService from 'ui/services/NetworkService';
import constants from 'ui/stores/filterset/constants';

import actions from './actions';

function* getFilterSets() {
  try {
    const response = yield call(NetworkService.fetchFilterSets);
    yield put(actions.filterSetsSuccess(response));
  } catch (err) {
    yield put(actions.filterSetsFail(err));
  }
}

function* deleteFilterSet(action) {
  const { id } = action;
  try {
    yield call(NetworkService.deleteFilterSet, { $id: id });
    yield put(actions.deleteFilterSetSuccess(id));
  } catch (err) {
    yield put(actions.deleteFilterSetFailure(err));
  } finally {
    yield put(actions.deleteFilterSetConfirm(undefined));
  }
}

export default function* filterSetsSaga() {
  yield takeLatest(constants.FILTER_SETS_REQUEST, getFilterSets);
  yield takeLatest(constants.DELETE_FILTER_SET_REQUEST, deleteFilterSet);
}
