import constants from './constants';

const saveFilterSetRequest = data => ({
  type: constants.SAVE_FILTER_SET_REQUEST,
  payload: { data },
});

const saveFilterSetSuccess = data => ({
  type: constants.SAVE_FILTER_SET_SUCCESS,
  payload: { data },
});

const saveFilterSetFailure = error => ({
  type: constants.SAVE_FILTER_SET_FAILURE,
  payload: error,
});

export default {
  saveFilterSetRequest,
  saveFilterSetSuccess,
  saveFilterSetFailure,
};
