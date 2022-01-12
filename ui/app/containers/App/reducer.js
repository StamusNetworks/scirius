import produce from 'immer';
import store from 'store';
import moment from 'moment';
import history from 'utils/history';
import { isEqual } from 'lodash';

import { TimePickerEnum } from 'ui/maps/TimePickersEnum';
import { StorageEnum } from 'ui/maps/StorageEnum';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { parseUrl } from 'ui/helpers/parseUrl';
import { getQueryObject } from 'ui/helpers/getQueryObject';
import { isBooted, setBooted } from 'ui/helpers/isBooted';
import constants from 'ui/containers/App/constants';

const initialTimeSpanStorage = store.get(StorageEnum.TIMESPAN) || {
  startDate: moment()
    .subtract(1, 'day')
    .format(),
  endDate: moment().format(),
  duration: 'H1',
  timePicker: TimePickerEnum.QUICK,
  minTimestamp: 0,
  maxTimestamp: 0,
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
    data: {
      system: {},
      global: {},
    },
    request: {
      loading: null,
      status: null,
      message: '',
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
      message: '',
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
      message: '',
    },
  },
};

/* eslint-disable default-case */
const appReducer = (state = initialState, action) =>
  produce(state, draft => {
    switch (action.type) {
      case constants.GET_SETTINGS_REQUEST:
        draft.settings.request.loading = true;
        draft.settings.request.status = null;
        draft.settings.request.message = '';
        break;
      case constants.GET_PERIOD_ALL_SUCCESS: {
        const { minTimestamp, maxTimestamp } = action.payload;
        draft.timespan.minTimestamp = minTimestamp;
        draft.timespan.maxTimestamp = maxTimestamp;
        store.set(StorageEnum.TIMESPAN, {
          ...(store.get(StorageEnum.TIMESPAN) || initialTimeSpanStorage),
          minTimestamp,
          maxTimestamp,
        });
        break;
      }
      case constants.GET_SETTINGS_SUCCESS: {
        draft.settings.data.system = action.payload.systemSettings;
        draft.settings.data.global = action.payload.globalSettings;
        draft.settings.request.loading = false;
        draft.settings.request.status = true;
        draft.settings.request.message = '';
        break;
      }
      case constants.GET_SETTINGS_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.settings.request.loading = false;
        draft.settings.request.status = false;
        draft.settings.request.message = `Global settings could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case constants.GET_USER_REQUEST:
        draft.user.request.loading = true;
        draft.user.request.status = null;
        draft.user.request.message = '';
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
        draft.user.request.message = '';
        break;
      case constants.GET_USER_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.user.data = {};
        draft.user.request.loading = false;
        draft.user.request.status = false;
        draft.user.request.message = `User could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
        break;
      }
      case constants.GET_SOURCE_REQUEST:
        draft.source.data = [];
        draft.source.request.loading = true;
        draft.source.request.status = null;
        draft.source.request.message = '';
        break;
      case constants.GET_SOURCE_SUCCESS:
        draft.source.data = action.payload.source;
        draft.source.request.loading = false;
        draft.source.request.status = true;
        draft.source.request.message = '';
        store.set(StorageEnum.SOURCE, [...action.payload.source]);
        break;
      case constants.GET_SOURCE_FAILURE: {
        const { httpCode, httpError, httpResponse } = action.payload;
        draft.source.data = [];
        draft.source.request.loading = false;
        draft.source.request.status = false;
        draft.source.request.message = `Sources could not be retrieved.\n${httpCode} ${httpError}\n ${httpResponse}`;
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

export default appReducer;
