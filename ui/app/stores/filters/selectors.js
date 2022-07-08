import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectRules = state => state.ruleSet || initialState;
const makeSelectRuleSets = () => createSelector(selectRules, subState => subState.filterSet);
const makeSelectFilterOptions = queryTypes =>
  createSelector(selectRules, subState => subState.filterList.filter(f => queryTypes.indexOf(f.queryType) !== -1 && f.filterType !== 'hunt'));
const makeSelectSupportedActions = () => createSelector(selectRules, subState => subState.supportedActions);
const makeSelectSaveFiltersModal = () => createSelector(selectRules, subState => subState.saveFiltersModal);

export default {
  makeSelectRuleSets,
  makeSelectFilterOptions,
  makeSelectSupportedActions,
  makeSelectSaveFiltersModal,
};
