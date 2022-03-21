import { fromJS } from 'immutable';
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
export const initialState = fromJS({
  filterSets: {
    global: [],
    private: [],
    static: [],
  },
  filterSetDeleteIdx: null,
  filterSetsLoading: false,
  filterSetsStatus: false,
  filterSetsMessage: '',
});

export const filterSetsReducer = (state = initialState, action) => {
  switch (action.type) {
    case FILTER_SETS_LOADING:
      return state
        .setIn(['filterSets', 'global'], fromJS([]))
        .setIn(['filterSets', 'private'], fromJS([]))
        .setIn(['filterSets', 'static'], fromJS([]))
        .set('filterSetsLoading', true)
        .set('filterSetsStatus', false)
        .set('filterSetsMessage', 'loading...');

    case FILTER_SETS_SUCCESS: {
      const { loadedFilterSets } = action;
      for (let idx = 0; idx < loadedFilterSets.length; idx += 1) {
        const row = loadedFilterSets[idx];

        row.pageTitle = huntTabs[page];
        // eslint-disable-next-line no-param-reassign
        state = state.updateIn(['filterSets', row.share], (list) => list.push(row));
      }
      return state.set('filterSetsLoading', false).set('filterSetsStatus', true).set('filterSetsMessage', '');
    }
    case FILTER_SETS_FAIL:
      return state
        .set('filterSetsList', fromJS([]))
        .set('filterSetsLoading', false)
        .set('filterSetsStatus', false)
        .set('filterSetsMessage', 'Filter sets could not be loaded');

    case DELETE_FILTER_SET:
      return state.set('filterSetsLoading', true).set('filterSetsStatus', false).set('filterSetsMessage', 'deleting filter set...');

    case DELETE_FILTER_SET_SUCCESS:
      return state
        .set('filterSetDeleteIdx', null)
        .set('filterSetsLoading', false)
        .set('filterSetsStatus', true)
        .set('filterSetsMessage', 'filter set deleted successfully')
        .setIn(
          ['filterSets', action.filterSetType],
          fromJS(
            state
              .getIn(['filterSets', action.filterSetType])
              .toJS()
              .filter((f) => f.id !== action.filterSetIdx),
          ),
        );

    default:
      return state;
  }
};

// SELECTORS
const makeSelectFiltersSetsStore = (state) => state.get('filterSets', initialState);
export const makeSelectGlobalFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.getIn(['filterSets', 'global']).toJS());
export const makeSelectPrivateFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.getIn(['filterSets', 'private']).toJS());
export const makeSelectStaticFilterSets = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.getIn(['filterSets', 'static']).toJS());
export const makeSelectFilterSetsLoading = () =>
  createSelector(makeSelectFiltersSetsStore, (filterSetsState) => filterSetsState.get('filterSetsLoading'));

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
