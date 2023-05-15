import constants from 'ui/stores/dashboard/constants';

const setEditMode = value => ({
  type: constants.SET_EDIT_MODE,
  payload: { value },
});

const setModalMoreResults = (visible, panelId, blockId) => ({
  type: constants.SET_MODAL_MORE_RESULTS,
  payload: { visible, panelId, blockId },
});

const downloadBlockData = (blockId, fileName) => ({
  type: constants.DOWNLOAD_BLOCK_DATA,
  payload: { fileName, blockId },
});

const getBlockMoreResultsRequest = blockId => ({
  type: constants.GET_BLOCK_MORE_RESULTS_REQUEST,
  payload: { blockId },
});

const getBlockMoreResultsSuccess = data => ({
  type: constants.GET_BLOCK_MORE_RESULTS_SUCCESS,
  payload: { data },
});

const getBlockMoreResultsFailure = (blockId, error) => ({
  type: constants.GET_BLOCK_MORE_RESULTS_FAILURE,
  payload: { blockId, error },
});

export default {
  setEditMode,
  downloadBlockData,
  setModalMoreResults,
  getBlockMoreResultsRequest,
  getBlockMoreResultsSuccess,
  getBlockMoreResultsFailure,
};
