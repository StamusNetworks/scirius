import produce from 'immer';
import store from 'store';
import moment from 'moment';
import history from 'utils/history';
import { isEqual } from 'lodash';
import { combineReducers } from 'redux';

import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { StorageEnum } from 'ui/maps/StorageEnum';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { parseUrl } from 'ui/helpers/parseUrl';
import { getQueryObject } from 'ui/helpers/getQueryObject';
import { isBooted, setBooted } from 'ui/helpers/isBooted';
import constants from 'ui/containers/App/constants';

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

const initialSettingsStorage = {
  system: {},
  global: {},
  ...store.get(StorageEnum.SETTINGS),
};

const initialSourceStorage = store.get(StorageEnum.SOURCE) || [];

const initialFiltersStorage = getQueryObject();

// The initial state of the App
export const initialState = {
  timespan: {
    // #4351 - Case: page load / refresh
    now: new Date().getTime(),
    ...initialTimeSpanStorage,
  },
  settings: {
    data: initialSettingsStorage,
    request: {
      loading: null,
      status: null,
    },
  },
  reload: {
    period: ReloadPeriodEnum.NONE,
    now: 0,
  },
  user: {
    data: {},
    request: {
      loading: null,
      status: null,
    },
  },
  filters: {
    ...initialFiltersStorage,
  },
  source: {
    data: [...initialSourceStorage],
    request: {
      loading: false,
      status: null,
    },
  },
};

/* eslint-disable default-case */
export const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.GET_SETTINGS_REQUEST:
        draft.settings.request.loading = true;
        draft.settings.request.status = null;
        break;
      case constants.GET_PERIOD_ALL_SUCCESS: {
        const { minTimestamp, maxTimestamp } = action.payload;
        const correct = !Number.isNaN(parseInt(minTimestamp, 10)) && !Number.isNaN(parseInt(maxTimestamp, 10));

        // D7 period is the default one if min/max timestamp boundaries are incorrect
        draft.timespan.minTimestamp = minTimestamp;
        draft.timespan.maxTimestamp = maxTimestamp;
        draft.timespan.duration = !correct && draft.timespan.duration === 'All' ? 'D7' : draft.timespan.duration;
        draft.timespan.disableAll = !correct;

        store.set(StorageEnum.TIMESPAN, {
          ...{
            ...initialTimeSpanStorage,
            ...store.get(StorageEnum.TIMESPAN),
          },
          duration: draft.timespan.duration,
          minTimestamp,
          maxTimestamp,
          disableAll: !correct,
        });

        break;
      }
      case constants.GET_SETTINGS_SUCCESS: {
        draft.settings.data.system = action.payload.systemSettings;
        draft.settings.data.global = action.payload.globalSettings;
        draft.settings.request.loading = false;
        draft.settings.request.status = true;
        store.set(StorageEnum.SETTINGS, {
          ...{
            ...initialSettingsStorage,
            ...store.get(StorageEnum.SETTINGS),
          },
          system: action.payload.systemSettings,
          global: action.payload.globalSettings,
        });
        break;
      }
      case constants.GET_SETTINGS_FAILURE: {
        draft.settings.request.loading = false;
        draft.settings.request.status = false;
        break;
      }
      case constants.GET_USER_REQUEST:
        draft.user.request.loading = true;
        draft.user.request.status = null;
        break;
      case constants.GET_USER_SUCCESS:
        draft.user.data = {
          allTenant: action.payload.all_tenant,
          noTenant: action.payload.no_tenant,
          tenants: action.payload.tenants,
          pk: action.payload.pk,
          timezone: action.payload.timezone,
          username: action.payload.username,
          firstName: action.payload.first_name,
          lastName: action.payload.last_name,
          isActive: action.payload.is_active,
          email: action.payload.email,
          dateJoined: action.payload.date_joined,
          permissions: action.payload.perms,
        };

        draft.user.request.loading = false;
        draft.user.request.status = true;
        break;
      case constants.GET_USER_FAILURE: {
        draft.user.data = {};
        draft.user.request.loading = false;
        draft.user.request.status = false;
        break;
      }
      case constants.GET_SOURCE_REQUEST:
        draft.source.data = [];
        draft.source.request.loading = true;
        draft.source.request.status = null;
        break;
      case constants.GET_SOURCE_SUCCESS:
        draft.source.data = action.payload.source;
        draft.source.request.loading = false;
        draft.source.request.status = true;
        store.set(StorageEnum.SOURCE, [...action.payload.source]);
        break;
      case constants.GET_SOURCE_FAILURE: {
        draft.source.data = [];
        draft.source.request.loading = false;
        draft.source.request.status = false;
        break;
      }
      case constants.SET_TIME_SPAN: {
        const { startDate, endDate } = action;
        draft.reload.now = new Date().getTime();
        draft.timespan.startDate = startDate;
        draft.timespan.endDate = endDate;
        draft.timespan.timePicker = TimePickerEnum.ABSOLUTE;
        store.set(StorageEnum.TIMESPAN, {
          ...(store.get(StorageEnum.TIMESPAN) || initialTimeSpanStorage),
          timePicker: TimePickerEnum.ABSOLUTE,
          startDate,
          endDate,
        });
        break;
      }
      case constants.SET_DURATION: {
        const { duration } = action;
        // #4351 - Case: time picker change (H1, H6, D1)
        draft.timespan.now = new Date().getTime();
        draft.timespan.duration = duration;
        draft.timespan.timePicker = TimePickerEnum.QUICK;
        store.set(StorageEnum.TIMESPAN, {
          ...(store.get(StorageEnum.TIMESPAN) || initialTimeSpanStorage),
          timePicker: TimePickerEnum.QUICK,
          duration,
        });
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
      case constants.LOCATION_CHANGE: {
        // #4351 - Case: location change
        draft.timespan.now = new Date().getTime();
        if (isBooted()) {
          draft.filters = parseUrl(history.location.search);
          store.set(StorageEnum.FILTERS, parseUrl(history.location.search));
        } else {
          if (isEqual(parseUrl(history.location.search), initialFiltersStorage)) {
            store.set(StorageEnum.FILTERS, parseUrl(history.location.search));
          }
          setBooted(true);
        }
        break;
      }
    }
  });

export default combineReducers({
  ce: appReducer,
});
