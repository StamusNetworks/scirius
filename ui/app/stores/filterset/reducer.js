import produce from 'immer';
import constants from 'ui/stores/filterset/constants';

export const initialState = {
  data: [],
  request: {
    get: {
      loading: false,
      status: null,
    },
    delete: {
      loading: false,
      status: null,
    },
  },
};

/* eslint-disable default-case */
const reducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.FILTER_SETS_REQUEST:
        draft.request.get.loading = true;
        draft.request.get.status = null;
        break;

      case constants.FILTER_SETS_SUCCESS: {
        const { data = [] } = action;
        for (let idx = 0; idx < data.length; idx += 1) {
          const row = data[idx];
          if (!draft.data.find(f => f.id === row.id)) {
            draft.data.push(row);
          }
        }
        draft.request.get.loading = false;
        draft.request.get.status = true;
        break;
      }
      case constants.FILTER_SETS_FAIL:
        draft.filterSetsList = [];
        draft.request.get.loading = false;
        draft.request.get.status = false;
        break;

      case constants.DELETE_FILTER_SET_REQUEST:
        draft.request.delete.loading = true;
        draft.request.delete.status = null;
        break;

      case constants.DELETE_FILTER_SET_SUCCESS:
        draft.request.delete.loading = false;
        draft.request.delete.status = true;
        draft.data = draft.data.filter(f => f.id !== action.id);
        break;

      case constants.DELETE_FILTER_SET_FAILURE:
        draft.request.delete.loading = false;
        draft.request.delete.status = false;
        break;
    }
  });

export default reducer;
