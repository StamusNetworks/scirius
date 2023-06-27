import { createSelector } from 'reselect';
import moment from 'moment';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { parseObjectToUrl } from 'ui/helpers/parseObjectToUrl';
import { initialState } from 'ui/containers/App/reducer';
import { getCurrentUser } from 'ui/helpers/getCurrentUser';

const selectGlobal = state => state.global.ce || initialState;

const selectRouter = state => state.router || { location: {} };

const selectCurrentUser = () => getCurrentUser();

/*
 * General selectors.
 *
 * Selectors which return raw data from the state.
 */

const makeSelectLocation = () => createSelector(selectRouter, routerState => routerState.location);

const makeSelectContext = () => createSelector(selectGlobal, subState => subState.context);

const makeSelectUpdatePushRuleset = () => createSelector(selectGlobal, subState => subState.updatePushRuleset);

const makeSelectStartDate = () =>
  createSelector(selectGlobal, subState => {
    if (subState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
      return moment(subState.timespan.startDate);
    }
    const { minTimestamp } = subState.timespan;
    if (subState.timespan.duration === 'All') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return !Number.isNaN(parseInt(minTimestamp, 10)) ? moment(minTimestamp) : moment().subtract(7, 'days');
    }
    return moment(subState.timespan.now).subtract(PeriodEnum[subState.timespan.duration].seconds, 'milliseconds');
  });

const makeSelectEndDate = () =>
  createSelector(selectGlobal, subState => {
    if (subState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
      return moment(subState.timespan.endDate);
    }
    const { maxTimestamp } = subState.timespan;
    if (subState.timespan.duration === 'All') {
      // D7 period is the default one if min/max timestamp boundaries are incorrect
      return !Number.isNaN(parseInt(maxTimestamp, 10)) ? moment(maxTimestamp) : moment();
    }
    return moment(subState.timespan.now);
  });

const makeSelectTimePicker = () => createSelector(selectGlobal, familiesState => familiesState.timespan.timePicker);

const makeSelectTimespan = () => createSelector(selectGlobal, familiesState => familiesState.timespan);

const makeSelectDuration = () => createSelector(selectGlobal, familiesState => familiesState.timespan.duration);

const makeSelectReload = () => createSelector(selectGlobal, subState => subState.reload);

const makeSelectReloadFlag = () => createSelector(selectGlobal, subState => subState.reload.now);

const makeSelectFilters = () => createSelector(selectGlobal, subState => subState.filters);

const makeSelectFilterSetsState = () => createSelector(selectGlobal, subState => subState.filterSets);

const makeSelectFiltersParam = () =>
  createSelector(selectGlobal, subState => {
    const filters = Object.assign({}, subState.filters);
    const urlParams = parseObjectToUrl(filters);
    return urlParams.length > 0 ? urlParams : '';
  });

const makeSelectCurrentUser = (param, fallback) =>
  createSelector(selectCurrentUser, currentUser => {
    if (param) {
      if (currentUser && typeof currentUser[param] !== 'undefined') {
        return currentUser[param];
      }
      return fallback;
    }
    return currentUser;
  });

/*
 * Network parameters selectors.
 *
 * Selectors which deliver state values as api url parameters.
 */

const makeSelectURLDates = createSelector([makeSelectStartDate(), makeSelectEndDate()], (startDate, endDate) => ({
  start_date: startDate.unix(),
  end_date: endDate.unix(),
}));

const makeSelectURLDatesES = createSelector(makeSelectURLDates, dates => ({
  from_date: dates.start_date * 1000,
  to_date: dates.end_date * 1000,
}));

/*
 * Returns all possible filter values as primitive dependencies in a single string.
 * It's intended to be used only in useEffect and other hooks
 * */
const makeSelectGlobalFiltersDependency = createSelector(selectGlobal, subState =>
  [subState.reload.now, subState.timespan.now, ...Object.values(subState.filters)].join(','),
);

export default {
  // General selectors
  selectGlobal,
  makeSelectLocation,
  makeSelectStartDate,
  makeSelectEndDate,
  makeSelectTimespan,
  makeSelectDuration,
  makeSelectTimePicker,
  makeSelectReload,
  makeSelectReloadFlag,
  makeSelectFilters,
  makeSelectFilterSetsState,
  makeSelectFiltersParam,
  makeSelectContext,
  makeSelectUpdatePushRuleset,
  makeSelectCurrentUser,
  // Network parameters selectors
  makeSelectURLDates,
  makeSelectURLDatesES,
  makeSelectGlobalFiltersDependency,
};
