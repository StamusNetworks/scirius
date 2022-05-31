import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectRules = state => state.ruleSet || initialState;
const makeSelectRuleSets = () => createSelector(selectRules, subState => subState.filterSet);
const makeSelectFilterOptions = (section) => createSelector(selectRules, subState => {
  if (section === 'history_filters') {
    return [
      {
        id: 'username',
        title: 'User',
        placeholder: 'Filter by User',
        filterType: 'text',
        queryType: 'all',
      },
      {
        id: 'comment',
        title: 'Comment',
        placeholder: 'Filter by Comment',
        filterType: 'text',
        queryType: 'all',
      },
      {
        id: 'action_type',
        title: 'Action Type',
        placeholder: 'Filter by Action Type',
        filterType: 'select',
        filterValues: subState.historyFilters,
        queryType: 'all',
      },
      {
        id: 'client_ip',
        title: 'Client IP',
        placeholder: 'Filter by Client IP',
        filterType: 'text',
        filterValues: [],
        queryType: 'all',
      },
    ];
  }
  return subState.filterList.filter(f => (f.queryType === 'filter' || f.queryType === 'rest') && f.filterType !== 'hunt')
});
const makeSelectSupportedActions = () => createSelector(selectRules, subState => subState.supportedActions);

export default {
  makeSelectRuleSets,
  makeSelectFilterOptions,
  makeSelectSupportedActions,
}
