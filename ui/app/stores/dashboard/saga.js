import { call, put, takeEvery, select } from 'redux-saga/effects';
import NetworkService from 'ui/services/NetworkService';
import { dashboard } from 'ui/config/Dashboard';
import constants from 'ui/stores/dashboard/constants';
import actions from 'ui/stores/dashboard/actions';
import { makeSelectGlobalFilters } from 'ui/containers/HuntApp/stores/global';
import selectors from 'ui/containers/App/selectors';
import { buildQFilter } from 'ui/buildQFilter';
import downloadData from 'ui/helpers/downloadData';

function* fetchDashboardMoreBlockData(action) {
  const { blockId } = action.payload;
  try {
    const response = yield call(retrieve, blockId, 30);
    const { [blockId]: data = [] } = response;
    yield put(actions.getBlockMoreResultsSuccess(data));
  } catch (e) {
    yield put(actions.getBlockMoreResultsFailure(e));
  }
}

function* fetchDashboardPanelData(action) {
  const { panelId } = action.payload;
  try {
    const fields = dashboard[panelId].items.map(item => item.i).join(',');
    const response = yield call(retrieve, fields, 5);
    yield put(actions.getDashboardPanelSuccess(panelId, response));
  } catch (e) {
    yield put(actions.getDashboardPanelFailure(panelId, e));
  }
}

function* retrieve(fields, pageSize) {
  const systemSettings = yield select(selectors.makeSelectSystemSettings());
  const filtersWithAlert = yield select(makeSelectGlobalFilters(true));
  const qfilter = (buildQFilter(filtersWithAlert, systemSettings) || '').replace('&qfilter=', '');
  const response = yield call(NetworkService.fetchDashboardPanel, {
    fields,
    qfilter,
    page_size: pageSize,
  });

  return response;
}

function* downloadBlockData(action) {
  const { fileName, blockId } = action.payload;
  try {
    const response = yield call(retrieve, blockId, 30);
    const { [blockId]: data = [] } = response;
    yield downloadData.text(data.map(o => o.key).join('\n'), fileName);
  } catch (e) {
    // do nothing
  }
}
export default function* rootSaga() {
  yield takeEvery(constants.GET_BLOCK_MORE_RESULTS_REQUEST, fetchDashboardMoreBlockData);
  yield takeEvery(constants.GET_DASHBOARD_PANEL_REQUEST, fetchDashboardPanelData);
  yield takeEvery(constants.DOWNLOAD_BLOCK_DATA, downloadBlockData);
}
