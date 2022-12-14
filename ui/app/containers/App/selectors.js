import { createSelector } from 'reselect';
import moment from 'moment';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { parseObjectToUrl } from 'ui/helpers/parseObjectToUrl';
import { initialState } from 'ui/containers/App/reducer';

const selectGlobal = state => state.global.ce || initialState;

const selectRouter = state => state.router || { location: {} };

/*
 * General selectors.
 *
 * Selectors which return raw data from the state.
 */

const makeSelectLocation = () => createSelector(selectRouter, routerState => routerState.location);

const makeSelectSystemSettings = () => createSelector(selectGlobal, subState => subState.settings.data);

const makeSelectUser = () => createSelector(selectGlobal, ({ user }) => user);

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

const makeSelectFiltersParam = (prefix = '&', skipStatus = false) =>
  createSelector(selectGlobal, subState => {
    const filters = Object.assign({}, subState.filters);
    if (skipStatus === true) {
      delete filters.status;
    }

    const urlParams = parseObjectToUrl(filters);
    return urlParams.length > 0 ? `${prefix}${urlParams}` : '';
  });

const makeSelectSource = () => createSelector(selectGlobal, subState => subState.source);

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

const makeSelectHasLicense = () => createSelector(selectGlobal, () => () => false);

export default {
  // General selectors
  selectGlobal,
  makeSelectLocation,
  makeSelectSystemSettings,
  makeSelectStartDate,
  makeSelectEndDate,
  makeSelectTimespan,
  makeSelectDuration,
  makeSelectTimePicker,
  makeSelectUser,
  makeSelectReload,
  makeSelectReloadFlag,
  makeSelectFilters,
  makeSelectFilterSetsState,
  makeSelectFiltersParam,
  makeSelectSource,
  makeSelectContext,
  makeSelectUpdatePushRuleset,
  // Network parameters selectors
  makeSelectURLDates,
  makeSelectURLDatesES,
  makeSelectGlobalFiltersDependency,
  makeSelectHasLicense,
};
