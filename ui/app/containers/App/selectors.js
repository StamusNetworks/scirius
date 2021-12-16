import { createSelector } from 'reselect';
import moment from 'moment';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { parseObjectToUrl } from 'ui/helpers/parseObjectToUrl';
import { initialState } from 'ui/containers/App/reducer';

const selectGlobal = state => state.global.ce || initialState;

const selectRouter = state => state.router || { location: {} };

const makeSelectLocation = () =>
  createSelector(
    selectRouter,
    routerState => routerState.location,
  );

const makeSelectGlobalSettings = () =>
  createSelector(
    selectGlobal,
    subState => subState.settings.data.global,
  );

const makeSelectSystemSettings = () =>
  createSelector(
    selectGlobal,
    subState => subState.settings.data.system,
  );

const makeSelectUser = () =>
  createSelector(
    selectGlobal,
    ({ user }) => user,
  );

const makeSelectStartDate = () =>
  createSelector(
    selectGlobal,
    subState => {
      if (subState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
        return moment(subState.timespan.startDate);
      }
      const { minTimestamp } = subState.timespan;
      if (subState.timespan.duration === 'All') {
        return moment(minTimestamp);
      }
      return moment().subtract(PeriodEnum[subState.timespan.duration].seconds, 'milliseconds');
    },
  );

const makeSelectEndDate = () =>
  createSelector(
    selectGlobal,
    subState => {
      if (subState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
        return moment(subState.timespan.endDate);
      }
      const { maxTimestamp } = subState.timespan;
      if (subState.timespan.duration === 'All') {
        return moment(maxTimestamp);
      }
      return moment();
    },
  );

const makeSelectGranularity = () =>
  createSelector(
    [selectGlobal, makeSelectStartDate(), makeSelectEndDate()],
    (subState, startDate, endDate) => {
      let result = 'years';
      const diff = endDate.unix()-startDate.unix();
      // less than or equal to 1 hour
      if (diff <= 60 * 60) {
        result = 'minutes';
      } // less than or equal to 2 days
      else if (diff <= 60 * 60 * 24 * 2) {
        result = 'hours';
      } // less than or equal to 30 days
      else if (diff <= 60 * 60 * 24 * 30) {
        result = 'days';
      } // less than or equal to 2 years
      else if (diff <= 60 * 60 * 24 * 365 * 2) {
        result = 'months';
      }
      return result;
    }
  );

const makeSelectTimePicker = () =>
  createSelector(
    selectGlobal,
    familiesState => familiesState.timespan.timePicker,
  );

const makeSelectDuration = () =>
  createSelector(
    selectGlobal,
    familiesState => familiesState.timespan.duration,
  );

const makeSelectReload = () =>
  createSelector(
    selectGlobal,
    subState => subState.reload,
  );

const makeSelectReloadFlag = () =>
  createSelector(
    selectGlobal,
    subState => subState.reload.now,
  );

const makeSelectFilters = () =>
  createSelector(
    selectGlobal,
    subState => subState.filters,
  );

const makeSelectFiltersParam = (prefix = '&', skipStatus = false) =>
  createSelector(
    selectGlobal,
    subState => {
      const filters = Object.assign({}, subState.filters);
      if (skipStatus === true) {
        delete filters.status;
      }
      const urlParams = parseObjectToUrl(filters);
      return urlParams.length > 0 ? `${prefix}${urlParams}` : '';
    },
  );

const makeSelectSource = () =>
  createSelector(
    selectGlobal,
    subState => subState.source,
  );

export default {
  selectGlobal,
  makeSelectLocation,
  makeSelectSystemSettings,
  makeSelectGlobalSettings,
  makeSelectStartDate,
  makeSelectEndDate,
  makeSelectDuration,
  makeSelectTimePicker,
  makeSelectUser,
  makeSelectReload,
  makeSelectReloadFlag,
  makeSelectFilters,
  makeSelectFiltersParam,
  makeSelectSource,
  makeSelectGranularity,
};
