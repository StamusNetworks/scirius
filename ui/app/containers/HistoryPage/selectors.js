import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectHistory = (state) => state.history || initialState;

const makeSelectActionTypesList = () => createSelector(selectHistory, (historyState) => historyState.actionTypesList);
const makeSelectHistoryList = () => createSelector(selectHistory, (historyState) => historyState.historyList);
const makeSelectHistoryFilters = () => createSelector(selectHistory, (historyState) => historyState.filters);

export { selectHistory, makeSelectActionTypesList, makeSelectHistoryList, makeSelectHistoryFilters };
