import { default as globalSelectors } from 'ui/containers/App/selectors';
import { createSelector } from 'reselect';

export const selectFilterParamsStore = state => state.filterParams || {};
export const makeSelectFilterParam = paramName => createSelector(selectFilterParamsStore, globalState => globalState[paramName]);
export const makeSelectFilterAbsolute = () => createSelector(selectFilterParamsStore, globalState => globalState.absolute);
export const makeSelectFilterParams = () =>
  createSelector([globalSelectors.makeSelectStartDate(), globalSelectors.makeSelectEndDate()], (startDate, endDate) => ({
    fromDate: startDate.unix() * 1000.0,
    toDate: endDate.unix() * 1000.0,
    duration: 0,
  }));
