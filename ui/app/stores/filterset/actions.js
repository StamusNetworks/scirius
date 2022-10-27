import constants from 'ui/stores/filterset/constants';

const loadFilterSetsRequest = () => ({
  type: constants.FILTER_SETS_REQUEST,
});

const filterSetsSuccess = data => ({
  type: constants.FILTER_SETS_SUCCESS,
  data,
});

const filterSetsFail = error => ({
  type: constants.FILTER_SETS_FAIL,
  error,
});

const deleteFilterSet = id => ({
  type: constants.DELETE_FILTER_SET_REQUEST,
  id,
});

const deleteFilterSetSuccess = (filterSetType, filterSetIdx) => ({
  type: constants.DELETE_FILTER_SET_SUCCESS,
  filterSetType,
  filterSetIdx,
});

const deleteFilterSetFail = error => ({
  type: constants.DELETE_FILTER_SET_FAILURE,
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
