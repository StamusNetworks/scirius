import produce from 'immer';
import constants from 'ui/stores/dashboard/constants';
import { createRef } from 'react';

/**
 * Convert empty keys to 'Unknown' values
 */
const sanitize = data => {
  const blockIds = Object.keys(data);
  if (blockIds.length > 0) {
    blockIds.forEach(blockId => {
      for (let idx = 0; idx < data[blockId].length; idx += 1) {
        data.nodeRef = createRef(null);
        if (!data[blockId][idx].key) {
          data[blockId][idx].key = 'Unknown';
        }
      }
    });
  }
  return data;
};

export const initialState = {
  panels: {},
  copyMode: false,
  more: {
    panelId: null,
    blockId: null,
    visible: false,
    data: [],
    status: null,
    loading: false,
  },
};

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.SET_EDIT_MODE: {
        draft.copyMode = action.payload.value;
        break;
      }
      // Load panel data
      case constants.GET_DASHBOARD_PANEL_REQUEST: {
        if (!draft.panels[action.payload.panelId]) {
          draft.panels[action.payload.panelId] = {
            data: {},
          };
        }
        draft.panels[action.payload.panelId].loading = true;
        draft.panels[action.payload.panelId].status = false;
        break;
      }
      case constants.GET_DASHBOARD_PANEL_SUCCESS: {
        draft.panels[action.payload.panelId].data = sanitize(action.payload.data);
        draft.panels[action.payload.panelId].loading = false;
        draft.panels[action.payload.panelId].status = false;
        break;
      }
      case constants.GET_DASHBOARD_PANEL_FAILURE: {
        draft.panels[action.payload.panelId].loading = false;
        draft.panels[action.payload.panelId].status = false;
        break;
      }
      // Load more block results
      case constants.SET_MODAL_MORE_RESULTS: {
        draft.more.visible = action.payload.visible;
        draft.more.panelId = action.payload.visible ? action.payload.panelId : null;
        draft.more.blockId = action.payload.visible ? action.payload.blockId : null;
        if (action.payload.visible) {
          draft.more.data = [];
        }
        break;
      }
      case constants.GET_BLOCK_MORE_RESULTS_REQUEST: {
        draft.more.visible = true;
        draft.more.data = [];
        draft.more.status = null;
        draft.more.loading = true;
        break;
      }
      case constants.GET_BLOCK_MORE_RESULTS_SUCCESS: {
        draft.more.data = sanitize(action.payload.data);
        draft.more.status = true;
        draft.more.loading = false;
        break;
      }
      case constants.GET_BLOCK_MORE_RESULTS_FAILURE: {
        draft.more.data = [];
        draft.more.status = false;
        draft.more.loading = false;
        break;
      }
    }
  });

export default appReducer;
