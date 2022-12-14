import { createSelector } from 'reselect';
import { initialState } from './reducer';

const selectDashboard = state => state.dashboard || initialState;
const makeSelectDashboardPanel = panelId => createSelector(selectDashboard, subState => subState.data.find(s => s.id === panelId));
const makeSelectDashboardPanels = () => createSelector(selectDashboard, subState => subState.panels);
const makeSelectDashboardPanelBlocks = panelId => createSelector(selectDashboard, subState => subState.data.find(s => s.id === panelId)?.items);
const makeSelectMoreResults = () => createSelector(selectDashboard, subState => subState.more);
const makeSelectCopyMode = () => createSelector(selectDashboard, subState => subState.copyMode);

export default {
  makeSelectDashboardPanel,
  makeSelectDashboardPanelBlocks,
  makeSelectDashboardPanels,
  makeSelectMoreResults,
  makeSelectCopyMode,
};
