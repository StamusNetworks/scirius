import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectRules = state => state.ruleSet || initialState;
const makeSelectRuleSets = () => createSelector(selectRules, subState => subState.filterSet);
const makeSelectFilterOptions = (section) => createSelector(selectRules, subState => {
  if (section === 'history_filters') {
    return [];
  }
  return subState.filterList.filter(f => (f.queryType === 'filter' || f.queryType === 'rest') && f.filterType !== 'hunt')
});
const makeSelectSupportedActions = () => createSelector(selectRules, subState => subState.supportedActions);

export default {
  makeSelectRuleSets,
  makeSelectFilterOptions,
  makeSelectSupportedActions,
}
