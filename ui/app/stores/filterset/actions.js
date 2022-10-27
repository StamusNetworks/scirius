import constants from 'ui/stores/filterset/constants';

const loadFilterSetsRequest = () => ({
  type: constants.FILTER_SETS_REQUEST,
});

const filterSetsSuccess = loadedFilterSets => ({
  type: constants.FILTER_SETS_SUCCESS,
  loadedFilterSets,
});

const filterSetsFail = error => ({
  type: constants.FILTER_SETS_FAIL,
  error,
});

const deleteFilterSet = (filterSetType, filterSet) => ({
  type: constants.DELETE_FILTER_SET,
  filterSetType,
  filterSet,
});

const deleteFilterSetSuccess = (filterSetType, filterSetIdx) => ({
  type: constants.DELETE_FILTER_SET_SUCCESS,
  filterSetType,
  filterSetIdx,
});

const deleteFilterSetFail = error => ({
  type: constants.DELETE_FILTER_SET_FAIL,
  error,
});

export default {
  loadFilterSetsRequest,
  filterSetsSuccess,
  filterSetsFail,
  deleteFilterSet,
  deleteFilterSetSuccess,
  deleteFilterSetFail,
};
