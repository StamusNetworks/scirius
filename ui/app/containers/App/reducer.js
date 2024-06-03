import produce from 'immer';
import moment from 'moment';
import { combineReducers } from 'redux';
import store from 'store';

import constants from 'ui/containers/App/constants';
import { getCurrentUser } from 'ui/helpers/getCurrentUser';
import { parseUrl } from 'ui/helpers/parseUrl';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { StorageEnum } from 'ui/maps/StorageEnum';
import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import history from 'utils/history';

const initialTimeSpanStorage = {
  startDate: moment().subtract(1, 'day').format(),
  endDate: moment().format(),
  duration: 'H1',
  timePicker: TimePickerEnum.QUICK,
  minTimestamp: null,
  maxTimestamp: null,
  // Disable All option by default. If the request returns good values then enable it in the reducer.
  disableAll: true,
  ...store.get(StorageEnum.TIMESPAN),
};

const initialFiltersStorage = parseUrl();

const hasMultiTenancy = getCurrentUser('multi_tenancy', false);
const availableTenants = getCurrentUser('tenants', []);
const firstAvailableTenant = availableTenants.length > 0 ? availableTenants[0] : undefined;

const validateTenantURLParam = tenantId => {
  if (hasMultiTenancy) {
    if (tenantId) {
      return !availableTenants.includes(parseInt(tenantId, 10)) ? firstAvailableTenant : tenantId;
    }
    return firstAvailableTenant;
  }
  return undefined;
};

// The initial state of the App
export const initialState = {
  timespan: {
    // #4351 - Case: page load / refresh
    now: new Date().getTime(),
    ...initialTimeSpanStorage,
  },
  reload: {
    period: ReloadPeriodEnum.NONE,
    now: 0,
  },
  filters: {
    ...initialFiltersStorage,
  },
  filterSets: false,
  updatePushRuleset: {
    request: { loading: false, status: null },
  },
};

/* eslint-disable default-case */
export const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.GET_PERIOD_ALL_SUCCESS: {
        const { minTimestamp, maxTimestamp } = action.payload;
        const correct = !Number.isNaN(parseInt(minTimestamp, 10)) && !Number.isNaN(parseInt(maxTimestamp, 10));

        // D7 period is the default one if min/max timestamp boundaries are incorrect
        draft.timespan.minTimestamp = minTimestamp;
        draft.timespan.maxTimestamp = maxTimestamp;
        draft.timespan.duration = !correct && draft.timespan.duration === 'All' ? 'D7' : draft.timespan.duration;
        draft.timespan.disableAll = !correct;
        break;
      }
      case constants.SET_TIME_SPAN: {
        const { startDate, endDate } = action;
        draft.reload.now = new Date().getTime();
        draft.timespan.startDate = startDate;
        draft.timespan.endDate = endDate;
        draft.timespan.timePicker = TimePickerEnum.ABSOLUTE;
        break;
      }
      case constants.SET_DURATION: {
        const { duration } = action;
        // #4351 - Case: time picker change (H1, H6, D1)
        draft.timespan.now = new Date().getTime();
        draft.timespan.duration = duration;
        draft.timespan.timePicker = TimePickerEnum.QUICK;
        break;
      }
      case constants.SET_RELOAD: {
        draft.reload.period = action.payload.reloadPeriod;
        break;
      }
      case constants.DO_RELOAD: {
        // #4351 - Case: reload button case
        draft.timespan.now = new Date().getTime();
        draft.reload.now = new Date().getTime();
        break;
      }
      case constants.SET_FILTER_SETS: {
        draft.filterSets = action.payload;
        break;
      }
      case constants.LOCATION_CHANGE: {
        // #4351 - Case: location change
        draft.timespan.now = new Date().getTime();
        const parsedUrl = parseUrl(history.location.search);
        if (process.env.NODE_ENV === 'production') {
          if (hasMultiTenancy) {
            if (parsedUrl.tenant) {
              parsedUrl.tenant = validateTenantURLParam(parsedUrl.tenant);
            }
          } else if (parsedUrl.tenant) {
            delete parsedUrl.tenant;
          }
        }
        draft.filters = parsedUrl;
        store.set(StorageEnum.FILTERS, parsedUrl);
        break;
      }
      case constants.UPDATE_PUSH_RULESET_RESET:
        draft.updatePushRuleset.request.loading = false;
        draft.updatePushRuleset.request.status = null;
        break;
      case constants.UPDATE_PUSH_RULESET_REQUEST:
        draft.updatePushRuleset.request.loading = true;
        draft.updatePushRuleset.request.status = null;
        break;
      case constants.UPDATE_PUSH_RULESET_SUCCESS:
        draft.updatePushRuleset.request.loading = false;
        draft.updatePushRuleset.request.status = true;
        break;
      case constants.UPDATE_PUSH_RULESET_FAILURE:
        draft.updatePushRuleset.request.loading = false;
        draft.updatePushRuleset.request.status = false;
        break;
    }
  });

export default combineReducers({
  ce: appReducer,
});
