import constants from 'ui/stores/filters/constants';

const ruleSetsRequest = () => ({
  type: constants.RULE_SETS_REQUEST,
});

const ruleSetsSuccess = data => ({
  type: constants.RULE_SETS_SUCCESS,
  payload: { data },
});

const ruleSetsFailure = error => ({
  type: constants.RULE_SETS_FAILURE,
  payload: { error },
});

const huntFilterRequest = () => ({
  type: constants.HUNT_FILTER_REQUEST,
});

const huntFilterSuccess = data => ({
  type: constants.HUNT_FILTER_SUCCESS,
  payload: { data },
});

const huntFilterFailure = error => ({
  type: constants.HUNT_FILTER_FAILURE,
  payload: { error },
});

const supportedActionsRequest = filters => ({
  type: constants.SUPPORTED_ACTIONS_REQUEST,
  payload: { filters },
});

const supportedActionsSuccess = data => ({
  type: constants.SUPPORTED_ACTIONS_SUCCESS,
  payload: { data },
});

const supportedActionsFailure = error => ({
  type: constants.SUPPORTED_ACTIONS_FAILURE,
  payload: { error },
});

const historyFiltersRequest = () => ({
  type: constants.HISTORY_FILTERS_REQUEST,
});

const historyFiltersSuccess = data => ({
  type: constants.HISTORY_FILTERS_SUCCESS,
  payload: { data },
});

const historyFiltersFailure = error => ({
  type: constants.HISTORY_FILTERS_FAILURE,
  payload: { error },
});

const saveFiltersModal = value => ({
  type: constants.MODAL_SAVE_FILTERS,
  payload: { value },
});

export default {
  ruleSetsRequest,
  ruleSetsSuccess,
  ruleSetsFailure,
  huntFilterRequest,
  huntFilterSuccess,
  huntFilterFailure,
  supportedActionsRequest,
  supportedActionsSuccess,
  supportedActionsFailure,
  historyFiltersRequest,
  historyFiltersSuccess,
  historyFiltersFailure,
  saveFiltersModal,
};
