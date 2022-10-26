import produce from 'immer';
import { createSelector } from 'reselect';
import { call, put, takeLatest } from 'redux-saga/effects';
import * as config from 'config/Api';
import axios from 'axios';

// CONSTANTS
const FILTER_SETS_REQUEST = 'Hunt/components/FilterSets/FILTER_SETS_REQUEST';
const FILTER_SETS_SUCCESS = 'Hunt/components/FilterSets/FILTER_SETS_SUCCESS';
const FILTER_SETS_FAIL = 'Hunt/components/FilterSets/FILTER_SETS_FAIL';
const DELETE_FILTER_SET = 'Hunt/components/FilterSets/DELETE_FILTER_SET';
const DELETE_FILTER_SET_SUCCESS = 'Hunt/components/FilterSets/DELETE_FILTER_SET_SUCCESS';
const DELETE_FILTER_SET_FAIL = 'Hunt/components/FilterSets/DELETE_FILTER_SET_FAIL';

// ACTIONS
export const loadFilterSetsRequest = () => ({
  type: FILTER_SETS_REQUEST,
});

export const filterSetsSuccess = loadedFilterSets => ({
  type: FILTER_SETS_SUCCESS,
  loadedFilterSets,
});

export const filterSetsFail = error => ({
  type: FILTER_SETS_FAIL,
  error,
});

export const deleteFilterSet = (filterSetType, filterSet) => ({
  type: DELETE_FILTER_SET,
  filterSetType,
  filterSet,
});

export const deleteFilterSetSuccess = (filterSetType, filterSetIdx) => ({
  type: DELETE_FILTER_SET_SUCCESS,
  filterSetType,
  filterSetIdx,
});

export const deleteFilterSetFail = error => ({
  type: DELETE_FILTER_SET_FAIL,
  error,
});

// REDUCER
export const initialState = {
  filterSets: {
    global: [],
    private: [],
    static: [],
  },
  filterSetDeleteIdx: null,
  filterSetsLoading: false,
  filterSetsStatus: null,
};

/* eslint-disable default-case */
export const filterSetsReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case FILTER_SETS_REQUEST:
        draft.filterSetsLoading = true;
        draft.filterSetsStatus = null;
        break;

      case FILTER_SETS_SUCCESS: {
        const { loadedFilterSets } = action;
        for (let idx = 0; idx < loadedFilterSets.length; idx += 1) {
          const row = loadedFilterSets[idx];
          // eslint-disable-next-line no-param-reassign
          if (!draft.filterSets[row.share].find(f => f.id === row.id)) {
            draft.filterSets[row.share].push(row);
          }
        }
        draft.filterSetsLoading = false;
        draft.filterSetsStatus = true;
        break;
      }
      case FILTER_SETS_FAIL:
        draft.filterSetsList = [];
        draft.filterSetsLoading = false;
        draft.filterSetsStatus = false;
        break;

      case DELETE_FILTER_SET:
        draft.filterSetsLoading = true;
        draft.filterSetsStatus = false;
        break;

      case DELETE_FILTER_SET_SUCCESS:
        draft.filterSetDeleteIdx = null;
        draft.filterSetsLoading = false;
        draft.filterSetsStatus = true;
        draft.filterSets[action.filterSetType] = draft.filterSets[action.filterSetType].filter(f => f.id !== action.filterSetIdx);
        break;
    }
  });

// SELECTORS
const makeSelectFiltersSetsStore = state => state.filterSets || initialState;
export const makeSelectGlobalFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.global);
export const makeSelectPrivateFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.private);
export const makeSelectStaticFilterSets = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSets.static);
export const makeSelectFilterSetsLoading = () => createSelector(makeSelectFiltersSetsStore, filterSetsState => filterSetsState.filterSetsLoading);

// SAGA
export function* getFilterSets() {
  const requestURL = `${config.API_URL}${config.HUNT_FILTER_SETS}`;
  try {
    const filterSetsResponse = yield call(axios.get, requestURL);
    yield put(filterSetsSuccess(filterSetsResponse.data));
  } catch (err) {
    yield put(filterSetsFail(err));
  }
}

export function* delFilterSet(action) {
  const { filterSet, filterSetType } = action;
  const requestURL = `${config.API_URL}${config.HUNT_FILTER_SETS}${filterSet.id}`;
  try {
    yield call(axios.delete, requestURL);
    yield put(deleteFilterSetSuccess(filterSetType, filterSet.id));
  } catch (err) {
    yield put(deleteFilterSetFail(err));
  }
}

export function* filterSetsSaga() {
  yield takeLatest(FILTER_SETS_REQUEST, getFilterSets);
  yield takeLatest(DELETE_FILTER_SET, delFilterSet);
}
