import { createSelector } from 'reselect';
import { call, put, takeLatest } from 'redux-saga/effects';
import * as config from 'config/Api';
import axios from 'axios';
import { huntTabs } from 'constants';

// CONSTANTS
const FILTER_SETS_LOADING = 'Hunt/components/FilterSets/FILTER_SETS_LOADING';
const FILTER_SETS_SUCCESS = 'Hunt/components/FilterSets/FILTER_SETS_SUCCESS';
const FILTER_SETS_FAIL = 'Hunt/components/FilterSets/FILTER_SETS_FAIL';
const DELETE_FILTER_SET = 'Hunt/components/FilterSets/DELETE_FILTER_SET';
const DELETE_FILTER_SET_SUCCESS = 'Hunt/components/FilterSets/DELETE_FILTER_SET_SUCCESS';
const DELETE_FILTER_SET_FAIL = 'Hunt/components/FilterSets/DELETE_FILTER_SET_FAIL';

// ACTIONS
export const loadFilterSets = () => ({
  type: FILTER_SETS_LOADING,
});

export const filterSetsSuccess = (loadedFilterSets) => ({
  type: FILTER_SETS_SUCCESS,
  loadedFilterSets,
});

export const filterSetsFail = (error) => ({
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

export const deleteFilterSetFail = (error) => ({
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
  filterSetsStatus: false,
  filterSetsMessage: '',
};

export const filterSetsReducer = (state = initialState, action) => {
  switch (action.type) {
    case FILTER_SETS_LOADING:
      state.filterSets.global = [];
      state.filterSets.private = [];
      state.filterSets.static = [];
      state.filterSetsLoading = true;
      state.filterSetsStatus = false;
      state.filterSetsMessage = 'loading...';
      return state;

    case FILTER_SETS_SUCCESS: {
      const { loadedFilterSets } = action;
      for (let idx = 0; idx < loadedFilterSets.length; idx += 1) {
        const row = loadedFilterSets[idx];

        row.pageTitle = huntTabs[page];
        // eslint-disable-next-line no-param-reassign
        state = state.filterSets[row.share].push(row);
      }
      state.filterSetsLoading = false;
      state.filterSetsStatus = true;
      state.filterSetsMessage = '';
      return state;
    }
    case FILTER_SETS_FAIL:
      state.filterSetsList = [];
      state.filterSetsLoading = false;
      state.filterSetsStatus = false;
      state.filterSetsMessage = 'Filter sets could not be loaded';
      return state;

    case DELETE_FILTER_SET:
      state.filterSetsLoading = true;
      state.filterSetsStatus = false;
      state.filterSetsMessage = 'deleting filter set...';
      return state;

    case DELETE_FILTER_SET_SUCCESS:
      state.filterSetDeleteIdx = null;
      state.filterSetsLoading = false;
      state.filterSetsStatus = true;
      state.filterSetsMessage = 'filter set deleted successfully';
      state.filterSets[action.filterSetType] = state.filterSets[action.filterSetType]
              .filter((f) => f.id !== action.filterSetIdx);
      return state;

    default:
      return state;
  }
};

// SELECTORS
const makeSelectFiltersSetsStore = (state) => state.filterSets || initialState;
export const makeSelectGlobalFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.filterSets.global);
export const makeSelectPrivateFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.filterSets.private);
export const makeSelectStaticFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.filterSets.static);
export const makeSelectFilterSetsLoading = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.filterSetsLoading);

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
  yield takeLatest(FILTER_SETS_LOADING, getFilterSets);
  yield takeLatest(DELETE_FILTER_SET, delFilterSet);
}
