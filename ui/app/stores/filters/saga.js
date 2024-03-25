import { call, put, takeEvery } from 'redux-saga/effects';

import NetworkService from 'ui/services/NetworkService';
import actions from 'ui/stores/filters/actions';
import constants from 'ui/stores/filters/constants';

function* getRuleSets() {
  try {
    const response = yield call(NetworkService.fetchRuleSets);
    const { results = [] } = response;
    yield put(actions.ruleSetsSuccess(results));
  } catch (e) {
    yield put(actions.ruleSetsFailure(e));
  }
}

function* getHuntFilters() {
  try {
    const response = yield call(NetworkService.fetchHuntFilter);
    yield put(actions.huntFilterSuccess(response || []));
  } catch (e) {
    yield put(actions.huntFilterFailure(e));
  }
}

function* getSupportedActions(action) {
  const { filters = [] } = action.payload;
  const fields = filters.map(f => f.id);
  try {
    const response = yield call(NetworkService.fetchSupportedActions, {}, { body: JSON.stringify({ fields }) });
    const { actions: data = [] } = response;
    yield put(actions.supportedActionsSuccess(data));
  } catch (e) {
    yield put(actions.supportedActionsFailure(e));
  }
}

function* getHistoryFilters() {
  try {
    const response = yield call(NetworkService.fetchHistoryFilters);
    const { action_type_list: data = [] } = response;
    yield put(actions.historyFiltersSuccess(data));
  } catch (e) {
    yield put(actions.historyFiltersFailure(e));
  }
}

export default function* rootSaga() {
  yield takeEvery(constants.RULE_SETS_REQUEST, getRuleSets);
  yield takeEvery(constants.HUNT_FILTER_REQUEST, getHuntFilters);
  yield takeEvery(constants.SUPPORTED_ACTIONS_REQUEST, getSupportedActions);
  yield takeEvery(constants.HISTORY_FILTERS_REQUEST, getHistoryFilters);
}
