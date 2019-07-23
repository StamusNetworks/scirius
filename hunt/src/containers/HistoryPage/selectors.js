import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectHistory = (state) => state.get('history', initialState);

const makeSelectActionTypesList = () => createSelector(selectHistory, (historyState) => historyState.get('actionTypesList').toJS());
const makeSelectHistoryList = () => createSelector(selectHistory, (historyState) => historyState.get('historyList'));
const makeSelectHistoryFilters = () => createSelector(selectHistory, (historyState) => historyState.get('filters').toJS());

export {
    selectHistory,
    makeSelectActionTypesList,
    makeSelectHistoryList,
    makeSelectHistoryFilters,
};
