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
    subState => subState.settings,
  );

const makeSelectUser = () =>
  createSelector(
    selectGlobal,
    ({ user }) => user,
  );

const makeSelectStartDate = () =>
  createSelector(
    selectGlobal,
    familiesState => {
      if (familiesState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
        return moment(familiesState.timespan.startDate);
      }
      return moment(parseInt((Date.now() / 60000).toFixed(0), 10) * 60000 - PeriodEnum[familiesState.timespan.duration].seconds);
    },
  );

const makeSelectEndDate = () =>
  createSelector(
    selectGlobal,
    familiesState => {
      if (familiesState.timespan.timePicker === TimePickerEnum.ABSOLUTE) {
        return moment(familiesState.timespan.endDate);
      }
      return moment(parseInt((Date.now() / 60000).toFixed(0), 10) * 60000);
    },
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
};
