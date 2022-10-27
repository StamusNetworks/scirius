import produce from 'immer';
import constants from 'ui/stores/filterset/constants';

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
const reducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.FILTER_SETS_REQUEST:
        draft.filterSetsLoading = true;
        draft.filterSetsStatus = null;
        break;

      case constants.FILTER_SETS_SUCCESS: {
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
      case constants.FILTER_SETS_FAIL:
        draft.filterSetsList = [];
        draft.filterSetsLoading = false;
        draft.filterSetsStatus = false;
        break;

      case constants.DELETE_FILTER_SET:
        draft.filterSetsLoading = true;
        draft.filterSetsStatus = false;
        break;

      case constants.DELETE_FILTER_SET_SUCCESS:
        draft.filterSetDeleteIdx = null;
        draft.filterSetsLoading = false;
        draft.filterSetsStatus = true;
        draft.filterSets[action.filterSetType] = draft.filterSets[action.filterSetType].filter(f => f.id !== action.filterSetIdx);
        break;
    }
  });

export default reducer;
