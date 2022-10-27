import { call, put, takeLatest } from 'redux-saga/effects';
import axios from 'axios';
import constants from 'ui/stores/filterset/constants';
import * as config from 'config/Api';
import actions from './actions';

function* getFilterSets() {
  const requestURL = `${config.API_URL}${config.HUNT_FILTER_SETS}`;
  try {
    const filterSetsResponse = yield call(axios.get, requestURL);
    yield put(actions.filterSetsSuccess(filterSetsResponse.data));
  } catch (err) {
    yield put(actions.filterSetsFail(err));
  }
}

function* delFilterSet(action) {
  const { filterSet, filterSetType } = action;
  const requestURL = `${config.API_URL}${config.HUNT_FILTER_SETS}${filterSet.id}`;
  try {
    yield call(axios.delete, requestURL);
    yield put(actions.deleteFilterSetSuccess(filterSetType, filterSet.id));
  } catch (err) {
    yield put(actions.deleteFilterSetFail(err));
  }
}

export default function* filterSetsSaga() {
  yield takeLatest(constants.FILTER_SETS_REQUEST, getFilterSets);
  yield takeLatest(constants.DELETE_FILTER_SET, delFilterSet);
}
